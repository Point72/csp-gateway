from datetime import datetime, timedelta
from inspect import getframeinfo, stack
from pprint import pprint
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    get_origin,
)

import csp
import numpy as np
import pandas as pd
from csp import ts
from pydantic import BaseModel, ConfigDict, Field

from csp_gateway import ChannelSelection, GatewayChannels, GatewayModule

__all__ = ("GatewayTestHarness",)

ChannelType = Union[str, Tuple[str, Any]]
T = TypeVar("T")


def assert_equal(actual, desired):
    """Implement custom equality assertion function"""
    # Right now we leverage numpy's, which is pretty general in that it handles standard objects,
    # nan's, and numpy arrays (containing nans)
    # Some things it might not handle properly are pd.NaT and pd.NA
    np.testing.assert_equal(actual, desired)


def assert_not_equal(actual, desired):
    # We do not use something like np.testing.assert_raises(AssertionError, assert_equal, actual, desired))
    # because when it fails, we want the error message in the assertion to show both actual/desired
    # As a result, this function won't handle numpy arrays well.
    if pd.isna(desired):
        assert pd.isna(actual)
    else:
        assert actual != desired


def assert_almost_equal(actual, desired):
    np.testing.assert_almost_equal(actual, desired)


class BaseGatewayTestEvent(BaseModel):
    """Base class for events that happen during the test.

    These events should not be constructed directly. Rather, they are constructed from the GatewayTestHarness
    """

    # Traceback info to help with debugging
    _lineno: int = None
    _filename: str = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Try to go two levels up in the stack, from where the helper functions on
        # GatewayTestHarness are themselves called.
        try:
            caller = getframeinfo(stack()[2][0])
            self._lineno = caller.lineno
            self._filename = caller.filename
        except Exception:
            pass

    def apply(self, now, values, tick_counts, ticked_values, *args, **kwargs) -> Optional[bool]:
        """Function to run inside the csp graph during runtime.
        If the function returns True, it will reset the state of ticked values and counts.
        """
        ...


class GatewayResetEvent(BaseGatewayTestEvent):
    """Event to explicitly reset the ticked counts and values."""

    def apply(self, *args, **kwargs):
        return True


class GatewayDelayEvent(BaseGatewayTestEvent):
    delay: Union[timedelta, datetime] = Field(
        timedelta(seconds=1), description="Time to wait before applying the event or the time to apply the event."
    )


class GatewayDataEvent(BaseGatewayTestEvent):
    """Event that sends data into the gateway"""

    channel: ChannelType
    value: Any  # GatewayStruct


class GatewayPrintEvent(BaseGatewayTestEvent):
    msg: str

    def apply(self, now, *args, **kwargs):
        print(f"{now}: {self.msg}")


class GatewayPrintTickedEvent(BaseGatewayTestEvent):
    def apply(self, now, values, *args, **kwargs):
        print(f"{now}: Ticked values:")
        pprint(values)


class GatewayPrintTickCountsEvent(BaseGatewayTestEvent):
    def apply(self, now, values, tick_counts, *args, **kwargs):
        print(f"{now}: Tick counts:")
        pprint(tick_counts)


class GatewayAssertTickCountsEqualEvent(BaseGatewayTestEvent):
    tick_counts: Dict[ChannelType, int]

    def apply(self, now, values, tick_counts, *args, **kwargs):
        assert tick_counts == self.tick_counts


class GatewayAssertTickCountEvent(BaseGatewayTestEvent):
    channel: ChannelType
    count: int

    def apply(self, now, values, tick_counts, *args, **kwargs):
        assert tick_counts.get(self.channel, 0) == self.count


class GatewayAssertEqualEvent(BaseGatewayTestEvent):
    channel: ChannelType
    value: Any
    almost: bool = False

    def apply(self, now, values, tick_counts, *args, **kwargs):
        if self.almost:
            assert_almost_equal(values[self.channel], self.value)
        else:
            assert_equal(values[self.channel], self.value)


class GatewayAssertTypeEvent(BaseGatewayTestEvent):
    channel: ChannelType
    value: Any

    def apply(self, now, values, tick_counts, *args, **kwargs):
        assert isinstance(values[self.channel], self.value)


class GatewayAssertAttrEqualEvent(BaseGatewayTestEvent):
    channel: ChannelType
    value: Any
    attr: str
    almost: bool = False

    def apply(self, now, values, tick_counts, *args, **kwargs):
        if self.almost:
            assert_almost_equal(getattr(values[self.channel], self.attr), self.value)
        else:
            assert_equal(getattr(values[self.channel], self.attr), self.value)


class GatewayAssertAttrsEqualEvent(BaseGatewayTestEvent):
    channel: ChannelType
    values: Dict[str, Any]
    almost: bool = False

    def apply(self, now, values, tick_counts, *args, **kwargs):
        for attr, value in self.values.items():
            if self.almost:
                assert_almost_equal(getattr(values[self.channel], attr), value)
            else:
                assert_equal(getattr(values[self.channel], attr), value)


class GatewayAssertAttrNotEqualEvent(BaseGatewayTestEvent):
    channel: ChannelType
    value: Any
    attr: str

    def apply(self, now, values, tick_counts, *args, **kwargs):
        assert_not_equal(getattr(values[self.channel], self.attr), self.value)


class GatewayAssertAttrUnsetEvent(BaseGatewayTestEvent):
    channel: ChannelType
    unset: bool
    attr: str

    def apply(self, now, values, tick_counts, *args, **kwargs):
        assert hasattr(values[self.channel], self.attr) == (not self.unset)


class GatewayAssertLenEvent(BaseGatewayTestEvent):
    channel: ChannelType
    value: int

    def apply(self, now, values, tick_counts, *args, **kwargs):
        assert len(values[self.channel]) == self.value


class GatewayAssertIdxTypeEvent(BaseGatewayTestEvent):
    channel: ChannelType
    idx: int
    value: Any

    def apply(self, now, values, tick_counts, *args, **kwargs):
        assert isinstance(values[self.channel][self.idx], self.value)


class GatewayAssertIdxAttrEqualEvent(BaseGatewayTestEvent):
    channel: ChannelType
    idx: int
    value: Any
    attr: str
    almost: bool = False

    def apply(self, now, values, tick_counts, *args, **kwargs):
        if self.almost:
            assert_almost_equal(getattr(values[self.channel][self.idx], self.attr), self.value)
        else:
            assert_equal(getattr(values[self.channel][self.idx], self.attr), self.value)


class GatewayAssertIdxAttrsEqualEvent(BaseGatewayTestEvent):
    channel: ChannelType
    idx: int
    values: Dict[str, Any]
    almost: bool = False

    def apply(self, now, values, tick_counts, *args, **kwargs):
        for attr, value in self.values.items():
            if self.almost:
                assert_almost_equal(getattr(values[self.channel][self.idx], attr), value)
            else:
                assert_equal(getattr(values[self.channel][self.idx], attr), value)


class GatewayAssertIdxAttrNotEqualEvent(BaseGatewayTestEvent):
    channel: ChannelType
    idx: int
    value: Any
    attr: str

    def apply(self, now, values, tick_counts, *args, **kwargs):
        assert_not_equal(getattr(values[self.channel][self.idx], self.attr), self.value)


class GatewayAssertIdxAttrUnsetEvent(BaseGatewayTestEvent):
    channel: ChannelType
    idx: int
    unset: bool
    attr: str

    def apply(self, now, values, tick_counts, *args, **kwargs):
        assert hasattr(values[self.channel][self.idx], self.attr) == (not self.unset)


class GatewayAssertTickedEvents(BaseGatewayTestEvent):
    channel: ChannelType
    assert_func: Callable[[Sequence[Tuple[datetime, Any]]], None]

    def apply(self, now, values, tick_counts, ticked_values, *args, **kwargs):
        self.assert_func(ticked_values[self.channel])


class GatewayEvaluateCallableEvent(BaseGatewayTestEvent):
    f: Callable[[], None]

    def apply(self, now, values, tick_counts, ticked_values, *args, **kwargs) -> Optional[bool]:
        self.f()
        return None


@csp.node
def _curve(data: List[Tuple[Union[datetime, timedelta], "T"]]) -> ts["T"]:
    """TODO: csp.curve doesn't allow mixing datetime and timedelta at the moment. Switch to csp.curve once supported."""
    with csp.alarms():
        alarm = csp.alarm(object)

    with csp.start():
        for t, datum in data:
            csp.schedule_alarm(alarm, t, datum)

    if csp.ticked(alarm):
        return alarm


class GatewayTestHarness(GatewayModule):
    name: str = "GatewayTestHarness"
    test_channels: ChannelSelection = Field(description="List of channels to test (both inputs and outputs)")
    events: List[BaseGatewayTestEvent] = []
    verbose: bool = False
    test_dynamic_keys: Dict[str, List[str]] = {}

    is_performance_test: bool = Field(
        default=False,
        description=(
            "Whether the test harness is running in a performance test. Normally outputs are captured so that "
            "assertions can be done on them, but this has some overhead. Turning performance test mode on causes "
            "the outputs to not be captured. This means that assertions will probably fail."
        ),
    )

    def dynamic_keys(self):
        return self.test_dynamic_keys

    def connect(self, channels: GatewayChannels) -> None:
        # Build a set of inputs based on the test cases
        # This is done statically at graph building time,
        # so that we can segregate the types properly for an arbitrary set of channels
        delta = timedelta(0)
        event_time = timedelta(0)
        reference_time = None
        event_curve_data = []
        test_channels = self.test_channels.select_from(channels=channels, all_fields=True)
        curve_data = {channel: [] for channel in test_channels}
        for event in self.events:
            if isinstance(event, GatewayDelayEvent):
                if isinstance(event.delay, timedelta):
                    delta += event.delay
                else:
                    # event.delay is a datetime.
                    if reference_time is not None:
                        if event_time > event.delay:
                            raise ValueError(f"Trying to move backwards in time from {event_time} to {event.delay}.")

                    reference_time = event.delay
                    delta = timedelta(0)

                if reference_time is None:
                    event_time = delta
                else:
                    event_time = reference_time + delta

            if isinstance(event, GatewayDataEvent):
                curve_data[event.channel].append((event_time, event.value))

            event_curve_data.append((event_time, event))

        channel_values = {}
        for channel in test_channels:
            outer_type = channels.get_outer_type(channel)
            if get_origin(outer_type) is dict:
                basket = channels.get_channel(channel)

                # Split the data events for the basket by basket key.
                basket_curve_data = {k: [] for k in basket.keys()}
                if curve_data[channel]:
                    for delta, basket_events in curve_data[channel]:
                        if not isinstance(basket_events, dict):
                            raise ValueError(f"Event values for dictionary baskets should be a dictionary, got {basket_events}.")

                        for k, v in basket_events.items():
                            if k not in basket:
                                raise ValueError(f"{k} is not a valid key in {channel}.")

                            basket_curve_data[k].append((delta, v))

                # Go through the basket, putting the values into channel_values and create the curves for
                # each basket key.
                curves = {}
                for k, v in basket.items():
                    # Channel output
                    channel_values[(channel, k)] = v
                    if self.verbose:
                        csp.print(f"Update {str((channel, k))}", v)

                    # Channel input
                    typ = v.tstype.typ
                    if basket_curve_data[k]:
                        curves[k] = _curve.using(T=typ)(basket_curve_data[k])
                    else:
                        curves[k] = csp.null_ts(typ)

                # Set input data to channel.
                channels.set_channel(channel, curves)
            else:
                typ = outer_type.typ
                if curve_data[channel]:
                    curve = _curve.using(T=typ)(curve_data[channel])
                else:
                    curve = csp.null_ts(typ)
                channels.set_channel(channel, curve)
                channel_values[channel] = channels.get_channel(channel)
                if self.verbose:
                    csp.print(f"Update {channel} ", channel_values[channel])

        if event_curve_data:
            event_curve = _curve.using(T=BaseGatewayTestEvent)(event_curve_data)
        else:
            event_curve = csp.null_ts(BaseGatewayTestEvent)

        # Run the tests
        self._run_test_events(event_curve, channel_values)

    @csp.node
    def _run_test_events(self, event: ts[BaseGatewayTestEvent], channel_values: Dict[object, ts[object]]):
        with csp.state():
            s_values = {}
            print(f"Starting {self.name}")

        with csp.stop():
            print(f"Finishing {self.name}")

        if csp.ticked(channel_values) and not self.is_performance_test:
            tickeditems = dict(channel_values.tickeditems())
            for channel, value in tickeditems.items():
                if channel not in s_values:
                    s_values[channel] = []

                if isinstance(channel, str) and channel.startswith("s_"):
                    s_values[channel].append((csp.now(), value.query()))
                else:
                    s_values[channel].append((csp.now(), value))

        if csp.ticked(event):
            try:
                current_values = {k: v[-1][1] for k, v in s_values.items() if len(v) > 0}
                tick_counts = {k: len(v) for k, v in s_values.items()}
                reset = event.apply(csp.now(), current_values, tick_counts, ticked_values=s_values)
            except AssertionError as e:
                print(f"Assertion failed in test at {event._filename}:{event._lineno}")
                raise e
            except Exception as e:
                print(f"Exception in test at {event._filename}:{event._lineno}")
                raise e
            if reset:
                s_values = {}

    def advance(self, *, delay: Union[timedelta, datetime] = timedelta(seconds=1), msg: str = "", pre_msg: str = "") -> None:  # noqa: B008
        """Convenience function to reset the state, and advance to the next part of the test by adding a delay.
        Optional messages are printed to help delimit sections of the test.

        Args:
            delay: Time to advance (timedelta) or the time (datetime) to advance to.
            msg: Message to print after the delay.
            pre_msg: Message to print before the delay.
        """
        self.reset()
        self.print(pre_msg)
        self.delay(delay)
        self.print(msg)

    def reset(self):
        self.events.append(GatewayResetEvent())

    def delay(self, delay: Union[timedelta, datetime]):
        """Move forward in time.

        Args:
            delay: Time to move forward by or the time to move forward to.
        """
        self.events.append(GatewayDelayEvent(delay=delay))

    def print(self, msg):
        self.events.append(GatewayPrintEvent(msg=msg))

    def print_ticked(self):
        self.events.append(GatewayPrintTickedEvent())

    def print_tick_counts(self):
        self.events.append(GatewayPrintTickCountsEvent())

    def send(self, channel, value):
        self.events.append(GatewayDataEvent(channel=channel, value=value))

    def assert_tick_counts(self, tick_counts):
        self.events.append(GatewayAssertTickCountsEqualEvent(tick_counts=tick_counts))

    def assert_ticked(self, channel, count=1):
        self.events.append(GatewayAssertTickCountEvent(channel=channel, count=count))

    def assert_equal(self, channel, value):
        self.events.append(GatewayAssertEqualEvent(channel=channel, value=value))

    def assert_almost_equal(self, channel, value):
        self.events.append(GatewayAssertEqualEvent(channel=channel, value=value, almost=True))

    def assert_type(self, channel, value):
        self.events.append(GatewayAssertTypeEvent(channel=channel, value=value))

    def assert_attr_equal(self, channel, attr, value):
        self.events.append(GatewayAssertAttrEqualEvent(channel=channel, attr=attr, value=value))

    def assert_attr_almost_equal(self, channel, attr, value):
        self.events.append(GatewayAssertAttrEqualEvent(channel=channel, attr=attr, value=value, almost=True))

    def assert_attrs_equal(self, channel, values):
        self.events.append(GatewayAssertAttrsEqualEvent(channel=channel, values=values))

    def assert_attrs_almost_equal(self, channel, values):
        self.events.append(GatewayAssertAttrsEqualEvent(channel=channel, values=values, almost=True))

    def assert_attr_not_equal(self, channel, attr, value):
        self.events.append(GatewayAssertAttrNotEqualEvent(channel=channel, attr=attr, value=value))

    def assert_attr_unset(self, channel, attr, unset=True):
        self.events.append(GatewayAssertAttrUnsetEvent(channel=channel, attr=attr, unset=unset))

    def assert_idx_type(self, channel, idx, value):
        self.events.append(GatewayAssertIdxTypeEvent(channel=channel, idx=idx, value=value))

    def assert_idx_attr_equal(self, channel, idx, attr, value):
        self.events.append(GatewayAssertIdxAttrEqualEvent(channel=channel, idx=idx, attr=attr, value=value))

    def assert_idx_attr_almost_equal(self, channel, idx, attr, value):
        self.events.append(GatewayAssertIdxAttrEqualEvent(channel=channel, idx=idx, attr=attr, value=value, almost=True))

    def assert_idx_attrs_equal(self, channel, idx, values):
        self.events.append(GatewayAssertIdxAttrsEqualEvent(channel=channel, idx=idx, values=values))

    def assert_idx_attrs_almost_equal(self, channel, idx, values):
        self.events.append(GatewayAssertIdxAttrsEqualEvent(channel=channel, idx=idx, values=values, almost=True))

    def assert_idx_attr_not_equal(self, channel, idx, attr, value):
        self.events.append(GatewayAssertIdxAttrNotEqualEvent(channel=channel, idx=idx, attr=attr, value=value))

    def assert_idx_attr_unset(self, channel, idx, attr, unset=True):
        self.events.append(GatewayAssertIdxAttrUnsetEvent(channel=channel, idx=idx, attr=attr, unset=unset))

    def assert_len(self, channel, value):
        self.events.append(GatewayAssertLenEvent(channel=channel, value=value))

    def assert_ticked_values(self, channel, assert_func: Callable[[Sequence[Tuple[datetime, Any]]], None]):
        """Apply an assert_func to the ticked values on a particular channel.

        :param channel: Channel to apply the assert_func on.
        :param assert_func: Function that accepts a sequence of ticked values on a channel represented as a sequence
            of tuples where the first item is the engine time of the tick and the second item is the ticked value.
            This function should raise an AssertionError if the ticked values is not what is expected.
        """
        self.events.append(GatewayAssertTickedEvents(channel=channel, assert_func=assert_func))

    def assert_value(self, channel, assert_func: Callable[[Any], None]):
        """Apply an assert_func to the current value on a particular channel.

        :param channel: Channel to apply the assert_func on.
        :param assert_func: Function that takes accepts the current value of a particular channel. This function should
            raise an AssertionError if the value is not what is expected.
        """

        def ticked_values_assert_func(ticked_values):
            assert len(ticked_values) > 0
            assert_func(ticked_values[-1][1])

        self.assert_ticked_values(channel, ticked_values_assert_func)

    def eval(self, f: Callable[[], None]):
        """Evaluate a function whilst the circuit is running. Useful for things like starting and stopping a profiler
        whilst the circuit is running."""
        self.events.append(GatewayEvaluateCallableEvent(f=f))
