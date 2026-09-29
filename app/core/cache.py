import threading
import time
from typing import Callable, TypeVar, cast

T = TypeVar("T")

_store: dict[str, tuple[float, object]] = {}
_lock = threading.Lock()
_MAX_ENTRIES = 500


def get_or_compute(
    key: str,
    ttl_seconds: int,
    compute: Callable[[], T],
    cacheable: Callable[[T], bool] = lambda _value: True,
) -> T:
    """
    Return a cached value if a fresh one exists, otherwise compute it.
    Only results the caller marks as cacheable are stored, so a failed
    lookup is never remembered.
    """
    with _lock:
        hit = _store.get(key)
        if hit is not None and hit[0] > time.monotonic():
            return cast(T, hit[1])

    value = compute()

    if cacheable(value):
        with _lock:
            if len(_store) >= _MAX_ENTRIES:
                _prune()
            _store[key] = (time.monotonic() + ttl_seconds, value)
    return value


def _prune() -> None:
    now = time.monotonic()
    for key in [k for k, (expires, _v) in _store.items() if expires <= now]:
        del _store[key]
    if len(_store) >= _MAX_ENTRIES:
        _store.clear()