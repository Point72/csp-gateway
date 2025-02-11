import asyncio
from asyncio import AbstractEventLoop, Future as AsyncFuture
from concurrent.futures import Future as ConcurrentFuture
from typing import Any, Dict, Union

import csp
from csp import ts
from csp.impl.genericpushadapter import GenericPushAdapter

EitherFutureType = Union[AsyncFuture, ConcurrentFuture]


class FutureAdapter(GenericPushAdapter):
    def __init__(self, kind: str, loop: AbstractEventLoop = None, name: str = None) -> None:
        if kind in ("async", AsyncFuture):
            super().__init__(AsyncFuture, name=name)
            self._kind = "async"
            self._loop = loop or asyncio.get_event_loop()
        else:
            super().__init__(ConcurrentFuture, name=name)
            self._kind = "concurrent"

    def push_tick(self, future: EitherFutureType = None) -> EitherFutureType:
        if self._kind == "async":
            fut = future or AsyncFuture(loop=self._loop)
        elif self._kind == "concurrent":
            fut = future or ConcurrentFuture()
        super().push_tick(fut)
        return fut


def on_request(value: ts[object], future: ts[object]):  # type: ignore[no-untyped-def]
    with csp.start():
        csp.make_passive(value)

    if csp.ticked(future):
        # TODO consider returning something other than None?
        to_return = value if csp.valid(value) else None

        if isinstance(future, AsyncFuture):
            future.get_loop().call_soon_threadsafe(future.set_result, to_return)

        elif isinstance(future, ConcurrentFuture):
            future.set_result(to_return)


on_request_node = csp.node(on_request)


def on_request_dict_basket(value: Dict[Any, ts[object]], future: ts[object]):  # type: ignore[no-untyped-def]
    with csp.start():
        csp.make_passive(value)

    if csp.ticked(future):
        # TODO consider returning something other than None?
        to_return = dict(value.validitems())  # type: ignore[attr-defined]

        if isinstance(future, AsyncFuture):
            future.get_loop().call_soon_threadsafe(future.set_result, to_return)

        elif isinstance(future, ConcurrentFuture):
            future.set_result(to_return)


on_request_node_dict_basket = csp.node(on_request_dict_basket)


def wait_for_next(value: ts[object], future: ts[object]):
    with csp.state():
        s_futures = []

    with csp.stop():
        # NOTE: resolve all dangling futures on shutdown
        for future in s_futures:
            if isinstance(future, AsyncFuture):
                # TODO use last value?
                future.get_loop().call_soon_threadsafe(future.set_result, None)

            elif isinstance(future, ConcurrentFuture):
                future.set_result(None)

    if csp.ticked(future):
        # save for later
        s_futures.append(future)

    if csp.ticked(value):
        for future in s_futures:
            if isinstance(future, AsyncFuture):
                future.get_loop().call_soon_threadsafe(future.set_result, value)

            elif isinstance(future, ConcurrentFuture):
                future.set_result(value)
        s_futures = []


wait_for_next_node = csp.node(wait_for_next)


def wait_for_next_dict_basket(value: Dict[Any, ts[object]], future: ts[object]):
    with csp.state():
        s_futures = []

    with csp.stop():
        # NOTE: resolve all dangling futures on shutdown
        for future in s_futures:
            if isinstance(future, AsyncFuture):
                # TODO use last value?
                future.get_loop().call_soon_threadsafe(future.set_result, None)

            elif isinstance(future, ConcurrentFuture):
                future.set_result(None)

    if csp.ticked(future):
        # save for later
        s_futures.append(future)

    if csp.ticked(value):
        # TODO consider returning something other than None?
        to_return = dict(value.validitems())  # type: ignore[attr-defined]

        for future in s_futures:
            if isinstance(future, AsyncFuture):
                future.get_loop().call_soon_threadsafe(future.set_result, to_return)

            elif isinstance(future, ConcurrentFuture):
                future.set_result(to_return)
        s_futures = []


wait_for_next_node_dict_basket = csp.node(wait_for_next_dict_basket)


def named_on_request_node(name: str) -> Any:
    # TODO this should work
    # csp.node(name=name)(on_request)
    node = csp.node(on_request)
    node.__name__ = name
    return node


def named_wait_for_next_node(name: str) -> Any:
    # TODO this should work
    # csp.node(name=name)(wait_for_next)
    node = csp.node(wait_for_next)
    node.__name__ = name
    return node


def named_on_request_node_dict_basket(name: str) -> Any:
    node = csp.node(on_request_dict_basket)
    node.__name__ = name
    return node


def named_wait_for_next_node_dict_basket(name: str) -> Any:
    node = csp.node(wait_for_next_dict_basket)
    node.__name__ = name
    return node


class AsyncFutureAdapter(FutureAdapter):
    def __init__(self, loop: AbstractEventLoop = None, name: str = None) -> None:
        super().__init__(kind="async", loop=loop, name=name)


class ConcurrentFutureAdapter(FutureAdapter):
    def __init__(self, name: str = None) -> None:
        super().__init__(kind="concurrent", name=name)
