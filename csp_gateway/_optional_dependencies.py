"""Which import failures mean "this extra is not installed" rather than "something is broken".

The re-export guards in `csp_gateway/__init__.py` and `csp_gateway/utils/__init__.py` have to let a
client-only install import cleanly, without also hiding genuine breakage inside modules that are
present. Telling those apart needs the import names each extra pulls in, since `pyproject.toml`
lists distributions and several of them import under a different name.
"""

from importlib.util import find_spec

CLIENT_OPTIONAL_IMPORTS = frozenset(
    {
        "httpx2",
        "jsonref",
        "nest_asyncio",
        "packaging",
        "pydantic",
    }
)

SERVER_OPTIONAL_IMPORTS = frozenset(
    {
        "atomic_counter",
        "ccflow",
        "colorlog",
        "csp",
        "deprecation",
        "duckdb",
        "fastapi",
        "fsspec",
        "httpx2",
        "hydra",
        "janus",
        "omegaconf",
        "orjson",
        "perspective",
        "psutil",
        "pyarrow",
        "pydantic",
        "spaday",
        "spaday_dagre",
        "spaday_perspective",
        "spaday_regular_layout",
        "spaday_webawesome",
        "uvicorn",
        "uvloop",
        "websockets",
    }
)


def _any_missing(optional_imports: frozenset[str]) -> bool:
    for module in optional_imports:
        try:
            if find_spec(module) is None:
                return True
        except (ImportError, ValueError):
            return True
    return False


def is_missing_optional_dependency(error: ImportError, optional_imports: frozenset[str]) -> bool:
    """True when `error` is `optional_imports` being absent rather than a real failure.

    Two shapes count. The dependency itself is missing, which names it directly. Or one of our own
    modules was left half-populated by an earlier suppressed failure, so the error names
    ``csp_gateway.*`` instead -- that second case only counts while a dependency really is absent,
    otherwise a circular import on a complete install would be swallowed, which is exactly what
    this guard exists to prevent.
    """
    failed = (error.name or "").split(".")[0]
    if failed in optional_imports:
        return True
    return failed == "csp_gateway" and _any_missing(optional_imports)
