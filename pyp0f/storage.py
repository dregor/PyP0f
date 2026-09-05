"""Write-only Redis sink: IP -> OS label, with a TTL.

No local state is kept beyond a small pending write buffer: observations are
pipelined and flushed in batches rather than one round-trip per packet, since
a plain per-packet SET becomes the bottleneck well before packet capture
itself does under sustained traffic. The buffer is bounded (flushed on size
or on a timer) and flush() is meant to be called once more on shutdown so the
last partial batch is not silently dropped.
"""
import threading
import time

import redis

from . import config

_client = redis.Redis(
    host=config.REDIS_HOST,
    port=config.REDIS_PORT,
    db=config.REDIS_DB,
    socket_timeout=1,
    socket_connect_timeout=1,
)
_pipe = _client.pipeline(transaction=False)
_lock = threading.Lock()
_pending = 0
_last_flush = time.monotonic()


def store(ip: str, os_label: str) -> None:
    global _pending, _last_flush

    key = f"{config.REDIS_KEY_PREFIX}{ip}"
    with _lock:
        _pipe.set(key, os_label, ex=config.REDIS_TTL_SECONDS)
        _pending += 1

        due = (
            _pending >= config.REDIS_BATCH_SIZE
            or time.monotonic() - _last_flush >= config.REDIS_FLUSH_INTERVAL_SECONDS
        )
        if due:
            _flush_locked()


def flush() -> None:
    """Flush any buffered writes now; safe to call on shutdown."""
    with _lock:
        _flush_locked()


def _flush_locked() -> None:
    global _pending, _last_flush

    if _pending:
        try:
            _pipe.execute()
        except redis.RedisError:
            # Best-effort: a lost batch just means those observations are
            # not cached; the next SYN from each client will retry.
            _pipe.reset()
    _pending = 0
    _last_flush = time.monotonic()
