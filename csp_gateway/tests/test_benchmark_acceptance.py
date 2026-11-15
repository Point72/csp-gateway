import json
import subprocess
import sys
from copy import deepcopy

import pytest
from pydantic import ValidationError

from csp_gateway.benchmarks.acceptance import AcceptanceTargets, evaluate_benchmark


@pytest.fixture
def targets():
    return AcceptanceTargets(
        engine_lag_p95_ms=50,
        engine_lag_peak_ms=250,
        last_p95_ms=100,
        max_bulk_rejection_fraction=0.05,
        min_windows=3,
        min_engine_lag_samples=100,
        min_state_offered=40,
    )


@pytest.fixture
def evidence():
    window = {
        "last": {"p95_ms": 10, "max_ms": 20},
        "engine_lag": {"samples": 1000, "p95_ms": 5, "max_ms": 10, "in_progress_ms": 0},
        "state_offered": 40,
        "state_succeeded": 40,
        "state_queue_full": 0,
        "state_queue_expired": 0,
        "state_timeouts": 0,
        "last_timeouts": 0,
        "ping_timeouts": 0,
    }
    return {"rounds": [deepcopy(window) for _ in range(3)]}


def test_acceptance_includes_exact_boundaries(targets, evidence):
    for window in evidence["rounds"]:
        window["last"] = {"p95_ms": 100, "max_ms": 120}
        window["engine_lag"] = {"samples": 1000, "p95_ms": 50, "max_ms": 250, "in_progress_ms": 0}
        window["state_succeeded"] = 38
        window["state_queue_full"] = 2
    result = evaluate_benchmark(evidence, targets)
    assert result["status"] == "pass"
    assert result["violations"] == []
    assert result["offered"] == 120
    assert result["succeeded"] == 114


@pytest.mark.parametrize(
    "section, field, observed, metric",
    [
        ("engine_lag", "p95_ms", 80, "engine_lag_p95_ms"),
        ("engine_lag", "max_ms", 300, "engine_lag_peak_ms"),
        ("last", "p95_ms", 150, "last_p95_ms"),
    ],
)
def test_acceptance_checks_every_window(targets, evidence, section, field, observed, metric):
    evidence["rounds"][2][section][field] = observed
    if field == "p95_ms":
        evidence["rounds"][2][section]["max_ms"] = max(observed, evidence["rounds"][2][section]["max_ms"])
    result = evaluate_benchmark(evidence, targets)
    assert result["status"] == "fail"
    assert any(violation["window"] == 3 and violation["metric"] == metric for violation in result["violations"])


def test_acceptance_does_not_hide_rejected_burst_in_aggregate(targets, evidence):
    window = evidence["rounds"][1]
    window.update(state_succeeded=37, state_queue_expired=3)
    result = evaluate_benchmark(evidence, targets)
    assert result["status"] == "fail"
    assert any(violation["window"] == 2 and violation["metric"] == "bulk_rejection_fraction" for violation in result["violations"])


def test_acceptance_flags_timeouts_separately(targets, evidence):
    evidence["rounds"][0].update(state_succeeded=39, state_timeouts=1)
    result = evaluate_benchmark(evidence, targets)
    assert result["status"] == "fail"
    assert any(violation["metric"] == "state_timeouts" for violation in result["violations"])


@pytest.mark.parametrize("missing", ["lag", "latency", "accounting", "nonfinite", "lag-samples"])
def test_acceptance_requires_complete_evidence(targets, evidence, missing):
    window = evidence["rounds"][0]
    if missing == "lag":
        del window["engine_lag"]
    elif missing == "latency":
        window["last"] = None
    elif missing == "accounting":
        window["state_succeeded"] = 35
    elif missing == "nonfinite":
        window["engine_lag"]["p95_ms"] = float("nan")
    else:
        window["engine_lag"]["samples"] = 1
    result = evaluate_benchmark(evidence, targets)
    assert result["status"] == "insufficient"
    assert result["evidence_errors"]


def test_acceptance_requires_enough_windows(targets, evidence):
    evidence["rounds"].pop()
    assert evaluate_benchmark(evidence, targets)["status"] == "insufficient"


@pytest.mark.parametrize("shortfall", ["lag_samples", "offered"])
def test_acceptance_requires_workload_evidence_floor(targets, evidence, shortfall):
    for window in evidence["rounds"]:
        if shortfall == "lag_samples":
            window["engine_lag"]["samples"] = 2
        else:
            window.update(state_offered=1, state_succeeded=1)
    result = evaluate_benchmark(evidence, targets)
    assert result["status"] == "insufficient"
    assert result["evidence_errors"]


def test_acceptance_checks_in_progress_engine_stall(targets, evidence):
    evidence["rounds"][2]["engine_lag"]["in_progress_ms"] = 500
    result = evaluate_benchmark(evidence, targets)
    assert result["status"] == "fail"
    assert result["worst_observed"]["engine_lag_peak_ms"] == 500
    assert any(violation["window"] == 3 and violation["metric"] == "engine_lag_peak_ms" for violation in result["violations"])


def test_acceptance_requires_in_progress_measurement(targets, evidence):
    del evidence["rounds"][0]["engine_lag"]["in_progress_ms"]
    assert evaluate_benchmark(evidence, targets)["status"] == "insufficient"


@pytest.mark.parametrize(
    "changes",
    [
        {"engine_lag_p95_ms": -1},
        {"engine_lag_peak_ms": 10},
        {"max_bulk_rejection_fraction": 1.1},
        {"min_windows": 0},
    ],
)
def test_acceptance_rejects_invalid_targets(targets, changes):
    with pytest.raises(ValidationError):
        AcceptanceTargets.model_validate({**targets.model_dump(), **changes})


def test_acceptance_targets_have_no_implicit_values():
    with pytest.raises(ValidationError):
        AcceptanceTargets()


@pytest.mark.parametrize("status", ["pass", "fail", "insufficient"])
def test_acceptance_cli_writes_report(tmp_path, targets, evidence, status):
    profile = tmp_path / "targets.json"
    source = tmp_path / "measurements.json"
    output = tmp_path / "report.json"
    if status == "fail":
        evidence["rounds"][0]["engine_lag"]["max_ms"] = 300
    elif status == "insufficient":
        evidence["rounds"] = []
    workload = {"materialize": False, "state_batch_rows": 500, "bulk_limit": 1, "cpu_work_ms": 5.0, "duration_s": 10.0}
    evidence.update(workload)
    profile.write_text(targets.model_dump_json())
    source.write_text(json.dumps({"benchmarks": [{"name": "example", "extra_info": evidence}]}))
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_gateway.benchmarks.acceptance",
            "--targets",
            str(profile),
            "--benchmarks",
            str(source),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == (0 if status == "pass" else 1), completed.stderr
    report = json.loads(output.read_text())
    assert report["targets"] == targets.model_dump()
    assert report["status"] == status
    assert report["results"][0]["status"] == status
    assert report["results"][0]["name"] == "example"
    assert report["results"][0]["workload"] == workload
