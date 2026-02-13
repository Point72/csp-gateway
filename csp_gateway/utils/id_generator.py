from datetime import datetime, timezone

from atomic_counter import Counter

# Single global ID generator shared across all classes
_global_counter = None


def _get_global_counter() -> Counter:
    """Get or create the single global ID counter."""
    global _global_counter
    if _global_counter is None:
        nowish = datetime.now(timezone.utc)
        base = datetime(nowish.year, nowish.month, nowish.day)
        _global_counter = Counter(int(base.timestamp()) * 1_000_000_000)
    return _global_counter


def get_counter() -> Counter:
    """Get the global ID counter.

    Returns the single shared counter used for generating unique IDs
    across all GatewayStruct classes.
    """
    return _get_global_counter()
