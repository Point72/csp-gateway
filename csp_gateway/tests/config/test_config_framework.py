"""The gateway picks its configuration framework in one place; this is that choice."""

import subprocess
import sys

import pytest


def _framework_under(env_value: str | None) -> str:
    """The framework a fresh interpreter selects, since the choice is made at import."""
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp"}
    if env_value is not None:
        env["CSP_GATEWAY_CONFIG_FRAMEWORK"] = env_value
    result = subprocess.run(
        [sys.executable, "-c", "from csp_gateway._config_framework import CONFIG_FRAMEWORK; print(CONFIG_FRAMEWORK)"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_lerna_is_preferred_when_unset():
    pytest.importorskip("lerna")
    assert _framework_under(None) == "lerna"


def test_hydra_can_be_pinned():
    assert _framework_under("hydra") == "hydra"


def test_lerna_can_be_pinned():
    pytest.importorskip("lerna")
    assert _framework_under("lerna") == "lerna"


def test_an_unknown_framework_is_rejected():
    # Rather than silently falling back, so a typo in the variable is not a mystery.
    from csp_gateway import _config_framework

    result = subprocess.run(
        [sys.executable, "-c", "import csp_gateway._config_framework"],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "CSP_GATEWAY_CONFIG_FRAMEWORK": "hydraa"},
        check=False,
    )
    assert result.returncode != 0
    assert "must be 'hydra', 'lerna', or unset" in result.stderr
    assert _config_framework.CONFIG_FRAMEWORK in ("hydra", "lerna")


def test_the_api_the_gateway_uses_is_present():
    from csp_gateway._config_framework import HydraConfig, hydra

    assert callable(hydra.main)
    assert callable(hydra.compose)
    assert callable(hydra.initialize_config_dir)
    assert hasattr(HydraConfig, "get")
