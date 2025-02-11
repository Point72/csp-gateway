from pydantic import TypeAdapter

from csp_gateway.server import ChannelSelection
from csp_gateway.testing.shared_helpful_classes import MyGatewayChannels


def test_selection():
    selection = ChannelSelection()
    channels = [
        "my_channel",
        "my_list_channel",
        "my_enum_basket",
        "my_str_basket",
        "my_enum_basket_list",
        "my_array_channel",
    ]
    static = ["my_static", "my_static_dict", "my_static_list"]

    assert selection.select_from(MyGatewayChannels) == channels
    assert selection.select_from(MyGatewayChannels, state_channels=True) == [
        "s_my_channel",
        "s_my_list_channel",
    ]
    assert selection.select_from(MyGatewayChannels, static_fields=True) == static


def test_selection_duplicates():
    channels = ["my_channel", "my_enum_basket"]
    static = ["my_static", "my_static_dict"]
    selection = ChannelSelection(include=channels + channels + static)

    assert selection.select_from(MyGatewayChannels) == channels
    assert selection.select_from(MyGatewayChannels, state_channels=True) == ["s_my_channel"]
    assert selection.select_from(MyGatewayChannels, static_fields=True) == static


def test_selection_all_fields():
    channels = ["my_enum_basket", "my_channel", "s_my_channel"]
    static = ["my_static", "my_static_dict"]
    selection = ChannelSelection(include=channels + static)

    assert selection.select_from(MyGatewayChannels, all_fields=True) == [
        "my_enum_basket",
        "my_channel",
        "s_my_channel",
        "my_static",
        "my_static_dict",
    ]


def test_selection_include():
    channels = ["my_channel", "my_enum_basket"]
    static = ["my_static", "my_static_dict"]
    selection = ChannelSelection(include=channels + static)

    assert selection.select_from(MyGatewayChannels) == channels
    assert selection.select_from(MyGatewayChannels, state_channels=True) == ["s_my_channel"]
    assert selection.select_from(MyGatewayChannels, static_fields=True) == static
    assert selection.select_from(MyGatewayChannels, all_fields=True) == [
        "my_channel",
        "my_enum_basket",
        "my_static",
        "my_static_dict",
    ]


def test_selection_exclude():
    selection = ChannelSelection(exclude=["my_channel", "my_enum_basket", "my_static"])
    channels = [
        "my_list_channel",
        "my_str_basket",
        "my_enum_basket_list",
        "my_array_channel",
    ]
    static = ["my_static_dict", "my_static_list"]

    assert selection.select_from(MyGatewayChannels) == channels
    assert selection.select_from(MyGatewayChannels, state_channels=True) == ["s_my_list_channel"]
    assert selection.select_from(MyGatewayChannels, static_fields=True) == static


def test_validate():
    selection = TypeAdapter(ChannelSelection).validate_python(["my_channel", "my_enum_basket"])
    assert selection.include == ["my_channel", "my_enum_basket"]

    selection = TypeAdapter(ChannelSelection).validate_python(None)
    assert selection.include is None
