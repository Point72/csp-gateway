import builtins
import runpy
import subprocess
import sys
import textwrap
from enum import Enum
from pathlib import Path

import pytest

FILTER_PATH = Path(__file__).parents[1] / "utils/web/filter.py"


def _run_python(source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(source)],
        capture_output=True,
        check=False,
        text=True,
    )


def test_internal_server_import_error_is_not_suppressed():
    result = _run_python(
        """
        import importlib.abc
        import importlib.util
        import sys

        class BrokenServerLoader(importlib.abc.Loader):
            def create_module(self, spec):
                return None

            def exec_module(self, module):
                raise ImportError(
                    "cannot import name 'GatewayWebApp' from partially initialized module 'csp_gateway.server'",
                    name="csp_gateway.server",
                )

        class BrokenServerFinder(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path, target=None):
                if fullname == "csp_gateway.server":
                    return importlib.util.spec_from_loader(fullname, BrokenServerLoader())
                return None

        sys.meta_path.insert(0, BrokenServerFinder())
        import csp_gateway
        """
    )

    assert result.returncode != 0
    assert "cannot import name 'GatewayWebApp'" in result.stderr
    assert "partially initialized module 'csp_gateway.server'" in result.stderr


def test_missing_server_dependency_is_suppressed():
    result = _run_python(
        """
        import importlib.abc
        import sys

        class MissingFastAPIFinder(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path, target=None):
                if fullname == "fastapi" or fullname.startswith("fastapi."):
                    raise ModuleNotFoundError("No module named 'fastapi'", name="fastapi")
                return None

        sys.meta_path.insert(0, MissingFastAPIFinder())
        import csp_gateway
        print("OK")
        """
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "OK\n"


def test_filter_allows_missing_csp(monkeypatch):
    original_import = builtins.__import__

    def missing_csp(name, *args, **kwargs):
        if name == "csp":
            raise ModuleNotFoundError("No module named 'csp'", name="csp")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_csp)
    namespace = runpy.run_path(FILTER_PATH)
    assert namespace["_ENUM_TYPES"] == (Enum,)


def test_filter_surfaces_broken_csp(monkeypatch):
    original_import = builtins.__import__

    def broken_csp(name, *args, **kwargs):
        if name == "csp":
            raise ImportError("csp internal dependency is broken", name="csp_internal")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", broken_csp)
    with pytest.raises(ImportError, match="csp internal dependency is broken"):
        runpy.run_path(FILTER_PATH)
