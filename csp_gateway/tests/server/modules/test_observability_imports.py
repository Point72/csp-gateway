from importlib import import_module

import pytest
from hydra.utils import get_class


@pytest.mark.parametrize(
    ("package", "module_name", "class_name"),
    [
        ("metrics", "datadog", "PublishDatadog"),
        ("metrics", "datadog", "PublishMetricsDatadog"),
        ("logging", "datadog_events", "PublishEventsDatadog"),
        ("alerts", "opsgenie", "PublishOpsGenie"),
        ("alerts", "opsgenie", "PublishAlertsOpsGenie"),
        ("heartbeats", "opsgenie", "PublishHeartbeatsOpsGenie"),
        ("chat", "symphony", "PublishSymphony"),
    ],
)
def test_publisher_import_paths(package, module_name, class_name):
    canonical_path = f"csp_gateway.server.modules.{package}.{module_name}"
    publisher = getattr(import_module(canonical_path), class_name)

    assert publisher.__module__ == canonical_path
    assert get_class(f"{canonical_path}.{class_name}") is publisher

    for namespace in (
        "csp_gateway",
        "csp_gateway.server",
        "csp_gateway.server.modules",
        "csp_gateway.server.modules.logging",
        f"csp_gateway.server.modules.logging.{module_name}",
        f"csp_gateway.server.modules.{package}",
    ):
        assert getattr(import_module(namespace), class_name) is publisher
        assert get_class(f"{namespace}.{class_name}") is publisher


@pytest.mark.parametrize(
    ("package", "module_name"),
    [("metrics", "datadog"), ("alerts", "opsgenie")],
)
def test_publisher_logger_names(package, module_name):
    module = import_module(f"csp_gateway.server.modules.{package}.{module_name}")

    assert module.log.name == f"csp_gateway.server.modules.logging.{module_name}"
