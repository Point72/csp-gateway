from json import dumps
from re import IGNORECASE, search
from typing import TYPE_CHECKING

from omegaconf import OmegaConf

from csp_gateway.server import GatewayChannels, GatewayModule

if TYPE_CHECKING:
    from csp_gateway.server.web.spaday_ui import GatewayUI


class MountConfig(GatewayModule):
    """Show the running instance's resolved Hydra configuration in a spaday tab."""

    def connect(self, channels: GatewayChannels) -> None:
        pass

    def ui(self, app: "GatewayUI") -> None:
        from spaday import element
        from spaday_webawesome import WaCallout, WaTree, WaTreeItem

        from csp_gateway.server.web.spaday_ui import Region

        def config_node(key, value, *, expanded=False):
            if search(r"password|passwd|secret|token|api[_-]?key|credential", str(key), IGNORECASE):
                value = "[redacted]"
            label = element("span").style(white_space="pre-wrap", overflow_wrap="anywhere")
            label.child(element("span").text(f"{key}: "))
            node = WaTreeItem(expanded=expanded).child(label)
            if isinstance(value, (dict, list)):
                is_object = isinstance(value, dict)
                preview = f"{{{len(value)} keys}}" if is_object else f"[{len(value)} items]"
                if not value:
                    preview = "{}" if is_object else "[]"
                label.child(element("span").text(preview).style(color="var(--spa-muted)"))
                children = value.items() if is_object else ((f"[{index}]", item) for index, item in enumerate(value))
                for child_key, child_value in children:
                    node.child(config_node(child_key, child_value))
            else:
                color = "var(--wa-color-success-on-quiet)" if isinstance(value, str) else "var(--wa-color-brand-on-quiet)"
                if value is None:
                    color = "var(--spa-muted)"
                label.child(element("span").text(dumps(value, ensure_ascii=False)).style(color=color))
            return node

        def config_tab():
            config = app.web_app.gateway._hydra_config
            if config is None:
                return WaCallout().text(
                    "Hydra configuration is unavailable. Start this gateway with the CLI or load_gateway() to view its configuration."
                )
            return (
                element("div", id="gateway-config")
                .child(
                    WaTree(selection="leaf")
                    .prop("aria-label", "Runtime configuration")
                    .child(config_node("Config", OmegaConf.to_container(OmegaConf.create(config)), expanded=True))
                )
                .style(
                    height="100%",
                    box_sizing="border-box",
                    margin="0",
                    padding="1rem",
                    overflow="auto",
                    overflow_wrap="anywhere",
                    font_family="ui-monospace, monospace",
                    font_size="0.875rem",
                )
            )

        app.add_tab("config", "Config", config_tab)
        app.add(Region.DRAWER_RIGHT, app.tab_button("Config", "config"))
