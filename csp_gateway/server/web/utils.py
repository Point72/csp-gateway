from typing import Any, Callable, Coroutine, Dict, Union

from fastapi.exceptions import RequestErrorModel

NoArgsNoReturnFuncT = Callable[[], None]
NoArgsNoReturnAsyncFuncT = Callable[[], Coroutine[Any, Any, None]]
NoArgsNoReturnDecorator = Callable[[Union[NoArgsNoReturnFuncT, NoArgsNoReturnAsyncFuncT]], NoArgsNoReturnAsyncFuncT]


class Error404(RequestErrorModel):  # type: ignore[misc, valid-type]
    detail: str = ""


def get_default_responses() -> Dict[Union[int, str], Dict[str, Any]]:
    return {404: {"model": Error404}}
