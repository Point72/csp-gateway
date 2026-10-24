import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class AcceptanceTargets(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    engine_lag_p95_ms: float = Field(gt=0, allow_inf_nan=False)
    engine_lag_peak_ms: float = Field(gt=0, allow_inf_nan=False)
    last_p95_ms: float = Field(gt=0, allow_inf_nan=False)
    max_bulk_rejection_fraction: float = Field(ge=0, le=1, allow_inf_nan=False)
    min_windows: int = Field(ge=1)
    min_engine_lag_samples: int = Field(ge=2)
    min_state_offered: int = Field(ge=1)

    @model_validator(mode="after")
    def _check_lag_limits(self):
        if self.engine_lag_peak_ms < self.engine_lag_p95_ms:
            raise ValueError("engine_lag_peak_ms must be at least engine_lag_p95_ms")
        return self


class _Latency(BaseModel):
    model_config = ConfigDict(strict=True)

    p95_ms: float = Field(ge=0, allow_inf_nan=False)
    max_ms: float = Field(ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def _check_order(self):
        if self.max_ms < self.p95_ms:
            raise ValueError("max_ms must be at least p95_ms")
        return self


class _EngineLag(_Latency):
    samples: int = Field(ge=2)
    in_progress_ms: float = Field(ge=0, allow_inf_nan=False)


class _Window(BaseModel):
    model_config = ConfigDict(strict=True)

    last: _Latency
    engine_lag: _EngineLag
    state_offered: int = Field(gt=0)
    state_succeeded: int = Field(ge=0)
    state_queue_full: int = Field(ge=0)
    state_queue_expired: int = Field(ge=0)
    state_timeouts: int = Field(ge=0)
    last_timeouts: int = Field(ge=0)
    ping_timeouts: int = Field(ge=0)

    @model_validator(mode="after")
    def _check_accounting(self):
        outcomes = self.state_succeeded + self.state_queue_full + self.state_queue_expired + self.state_timeouts
        if outcomes != self.state_offered:
            raise ValueError("bulk outcomes must equal offered requests")
        return self


def evaluate_benchmark(evidence: dict[str, Any], targets: AcceptanceTargets) -> dict[str, Any]:
    rounds = evidence.get("rounds", [])
    workload_keys = (
        "materialize",
        "state_batch_rows",
        "bulk_limit",
        "queue_limit",
        "queue_timeout_s",
        "cpu_work_ms",
        "duration_s",
        "changing_bursts",
    )
    result: dict[str, Any] = {
        "status": "pass",
        "violations": [],
        "evidence_errors": [],
        "workload": {key: evidence[key] for key in workload_keys if key in evidence},
    }
    if not isinstance(rounds, list):
        result["status"] = "insufficient"
        result["evidence_errors"].append({"window": None, "reason": "rounds must be a list"})
        return result
    result["window_count"] = len(rounds)
    if len(rounds) < targets.min_windows:
        result["evidence_errors"].append({"window": None, "reason": f"requires at least {targets.min_windows} windows"})
    valid = []
    observations = []
    for number, raw in enumerate(rounds, 1):
        try:
            window = _Window.model_validate(raw)
        except ValidationError as error:
            details = error.errors(include_input=False, include_context=False, include_url=False)
            result["evidence_errors"].append({"window": number, "details": details})
            continue
        valid.append(window)
        if window.engine_lag.samples < targets.min_engine_lag_samples:
            result["evidence_errors"].append({"window": number, "reason": f"requires at least {targets.min_engine_lag_samples} engine-lag samples"})
        if window.state_offered < targets.min_state_offered:
            result["evidence_errors"].append({"window": number, "reason": f"requires at least {targets.min_state_offered} offered bulk requests"})
        rejected = (window.state_queue_full + window.state_queue_expired) / window.state_offered
        metrics = {
            "engine_lag_p95_ms": (window.engine_lag.p95_ms, targets.engine_lag_p95_ms),
            "engine_lag_peak_ms": (max(window.engine_lag.max_ms, window.engine_lag.in_progress_ms), targets.engine_lag_peak_ms),
            "last_p95_ms": (window.last.p95_ms, targets.last_p95_ms),
            "bulk_rejection_fraction": (rejected, targets.max_bulk_rejection_fraction),
            "state_timeouts": (window.state_timeouts, 0),
            "last_timeouts": (window.last_timeouts, 0),
            "ping_timeouts": (window.ping_timeouts, 0),
        }
        observations.append({name: observed for name, (observed, _) in metrics.items()})
        for name, (observed, limit) in metrics.items():
            if observed > limit:
                result["violations"].append({"window": number, "metric": name, "observed": observed, "limit": limit})
    result["valid_window_count"] = len(valid)
    result["offered"] = sum(window.state_offered for window in valid) if len(valid) == len(rounds) else None
    result["succeeded"] = sum(window.state_succeeded for window in valid) if len(valid) == len(rounds) else None
    result["worst_observed"] = {name: max(row[name] for row in observations) for name in observations[0]} if observations else {}
    if result["evidence_errors"]:
        result["status"] = "insufficient"
    elif result["violations"]:
        result["status"] = "fail"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate measured admission policies against application-supplied objectives.")
    parser.add_argument("--targets", required=True, type=Path)
    parser.add_argument("--benchmarks", required=True, nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    targets = AcceptanceTargets.model_validate_json(args.targets.read_text())
    results = []
    for source in args.benchmarks:
        document = json.loads(source.read_text())
        for benchmark in document.get("benchmarks", []):
            result = evaluate_benchmark(benchmark.get("extra_info", {}), targets)
            result.update(name=benchmark.get("name"), source=str(source))
            results.append(result)
    if not results or any(result["status"] == "insufficient" for result in results):
        status = "insufficient"
    elif any(result["status"] == "fail" for result in results):
        status = "fail"
    else:
        status = "pass"
    report = {"status": status, "targets": targets.model_dump(), "results": results}
    encoded = json.dumps(report, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
        print(args.output)
    else:
        print(encoded, end="")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
