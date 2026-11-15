import os
import subprocess
import sys
from pathlib import Path

import pytest


def _framework_under(
    env_value: str | None,
    *,
    hidden_modules: tuple[str, ...] = (),
    code: str = "print(module.CONFIG_FRAMEWORK)",
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("CCFLOW_CONFIG_BACKEND", None)
    env.pop("CSP_GATEWAY_CONFIG_FRAMEWORK", None)
    if env_value is not None:
        env["CCFLOW_CONFIG_BACKEND"] = env_value
    module_path = Path(__file__).resolve().parents[2] / "_config_framework.py"
    return subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import importlib.util, sys; "
                f"sys.modules.update(dict.fromkeys({hidden_modules!r})); "
                f"spec = importlib.util.spec_from_file_location('_config_framework', {str(module_path)!r}); "
                "module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); " + code
            ),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


@pytest.mark.parametrize("env_value", [None, "", "hydra", "hydraa"])
def test_hydra_is_preferred_when_available(env_value):
    pytest.importorskip("hydra")
    pytest.importorskip("lerna")
    result = _framework_under(env_value)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "hydra"


@pytest.mark.parametrize("env_value", ["lerna", " LERNA "])
def test_lerna_can_be_selected_explicitly(env_value):
    pytest.importorskip("lerna")
    result = _framework_under(env_value)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "lerna"


@pytest.mark.parametrize("env_value", [None, "hydra", "hydraa"])
def test_lerna_is_used_when_hydra_is_unavailable(env_value):
    pytest.importorskip("lerna")
    result = _framework_under(env_value, hidden_modules=("hydra",))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "lerna"


def test_hydra_is_used_when_lerna_is_unavailable():
    pytest.importorskip("hydra")
    result = _framework_under(None, hidden_modules=("lerna",))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "hydra"


def test_explicit_unavailable_lerna_fails_clearly():
    result = _framework_under("lerna", hidden_modules=("lerna",))
    assert result.returncode != 0
    assert "CCFLOW_CONFIG_BACKEND=lerna requires the 'lerna' package" in result.stderr


@pytest.mark.parametrize("env_value", [None, "hydra", "hydraa"])
def test_missing_frameworks_fail_clearly(env_value):
    result = _framework_under(env_value, hidden_modules=("hydra", "lerna"))
    assert result.returncode != 0
    assert "requires 'hydra-core' or 'lerna'" in result.stderr


def test_missing_backend_dependency_is_not_hidden_by_fallback():
    pytest.importorskip("hydra")
    result = _framework_under(
        None,
        hidden_modules=("omegaconf",),
        code="sys.modules['lerna'] = object(); print(module.CONFIG_FRAMEWORK)",
    )
    assert result.returncode != 0
    assert "ModuleNotFoundError" in result.stderr
    assert "omegaconf" in result.stderr


def test_import_does_not_require_a_backend():
    result = _framework_under(None, hidden_modules=("hydra", "lerna"), code="print('imported')")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "imported"


def test_backend_selection_is_cached_across_api_accesses():
    pytest.importorskip("hydra")
    pytest.importorskip("lerna")
    result = _framework_under(
        None,
        code=(
            "import os; print(module.CONFIG_FRAMEWORK); "
            "os.environ['CCFLOW_CONFIG_BACKEND'] = 'lerna'; "
            "print(module.CONFIG_FRAMEWORK); print(module.hydra.__name__); print(module.HydraConfig.__module__)"
        ),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["hydra", "hydra", "hydra", "hydra.core.hydra_config"]


def test_the_api_the_gateway_uses_is_present():
    from csp_gateway._config_framework import HydraConfig, hydra

    assert callable(hydra.main)
    assert callable(hydra.compose)
    assert callable(hydra.initialize_config_dir)
    assert hasattr(HydraConfig, "get")
