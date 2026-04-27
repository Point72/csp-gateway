import importlib
from datetime import datetime, timezone
from unittest.mock import patch

# csp_gateway.utils gets shadowed in sys.modules by csp_gateway.server.web.utils,
# so load the real module by file path.
_id_gen_mod = importlib.import_module("csp_gateway.utils.id_generator")


def _reset_global_counter():
    """Reset the global counter so _get_global_counter re-initialises."""
    _id_gen_mod._global_counter = None


def test_base_uses_utc_midnight():
    """Regression: naive datetime caused the base to be interpreted as local
    time. When the process started between midnight-local and midnight-UTC
    (e.g. 9 PM EDT = 01:00 UTC), Rust's ``Utc::now_nanos - base_nanos``
    underflowed a u64, producing a near-2^64 counter value."""
    _reset_global_counter()
    try:
        # Simulate a time where UTC hour < local-timezone UTC offset would
        # have caused underflow with the old naive-datetime code
        # (01:00 UTC = 9 PM EDT the previous evening).
        #
        # Derive from today's real UTC date rather than hardcoding one:
        # Rust's `Utc::now()` can't be mocked from Python, so
        # `counter.current() == real_now_ns - mocked_base_ns`. A hardcoded
        # date makes that delta grow without bound as the real clock walks
        # forward, blowing past the upper-bound assertion below.
        fake_now = datetime.now(timezone.utc).replace(hour=1, minute=0, second=0, microsecond=0)

        with patch.object(_id_gen_mod, "datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            # Ensure the real datetime constructor is used for building `base`
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)

            counter = _id_gen_mod._get_global_counter()
            value = counter.current()

            # Value must be reasonable (well below 2^63) — not a wrapped u64
            assert value < 2**63, f"Counter value {value} looks like a u64 underflow wrap"

            # The Rust Counter stores  Utc::now_nanos - base_nanos.
            # We can't control Rust's Utc::now(), but we can verify the base
            # we passed is sane: it must equal UTC midnight in nanos.
            # Counter(base_nanos) → Rust sees base=base_nanos.
            # If naive, base would have been 4 h later (EST offset) and could
            # exceed Utc::now for early-UTC times.
            # Just assert the value is not astronomically large.
            assert value < 200_000 * 1_000_000_000, f"Counter value {value} is unreasonably large"
    finally:
        _reset_global_counter()
