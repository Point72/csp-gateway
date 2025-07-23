import asyncio
from typing import Any, Dict, List

from fastapi.responses import Response

__all__ = (
    "prepare_response",
    "get_next_tick",
)


def prepare_response(
    res: Any,
    is_list_model: bool = False,
    is_dict_basket: bool = False,
    wrap_in_response: bool = True,
) -> List[Dict[Any, Any]]:
    # If we've ticked
    if res:
        # Convert the dict basket to just the list of values
        if is_dict_basket:
            res = res.values()

        # If its not a list model, it means we got back 1 thing, so wrap it
        elif not is_list_model and not isinstance(res, list):
            res = [res]

    else:
        #  Else return an empty json
        res = []

    json_res_bytes = b"[" + b",".join(r.type_adapter().dump_json(r) for r in res) + b"]"
    json_res = json_res_bytes.decode()
    # Prepare and return response
    if wrap_in_response:
        return Response(
            content=json_res,
            media_type="application/json",
        )
    # useful when you want the data, but outside a fastapi response object
    return json_res


async def get_next_tick(gateway, field, key=""):
    """Need to do some fanciness so that a `next` call doesnt block the webserver"""
    return await asyncio.get_event_loop().run_in_executor(None, gateway.channels.next, field, key)
