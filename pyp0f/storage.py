"""Write-only Redis sink: IP -> OS label, with a TTL.

No local state is kept beyond a small pending write buffer: observations are
pipelined and flushed in batches rather than one round-trip per packet, since
a plain per-packet SET becomes the bottleneck well before packet capture
itself does under sustained traffic. The buffer is bounded (flushed on size
or on a timer) and flush() is meant to be called once more on shutdown so the
last partial batch is not silently dropped.

A class (rather than module-level globals) so tests can construct isolated
instances against a fake Redis client instead of sharing process-wide state.
"""
import logging
import threading
import time

import redis

from . import config

log = logging.getLogger("pyp0f.storage")


class RedisSink:
    def __init__(
        self,
        client: "redis.Redis | None" = None,
        key_prefix: str = config.REDIS_KEY_PREFIX,
        ttl_seconds: int = config.REDIS_TTL_SECONDS,
        batch_size: int = config.REDIS_BATCH_SIZE,
        flush_interval_seconds: float = config.REDIS_FLUSH_INTERVAL_SECONDS,
    ) -> None:
        self._client = client or redis.Redis(
            host=config.REDIS_HOST,
            port=config.REDIS_PORT,
            db=config.REDIS_DB,
            socket_timeout=1,
            socket_connect_timeout=1,
        )
        self._pipe = self._client.pipeline(transaction=False)
        self._key_prefix = key_prefix
        self._ttl_seconds = ttl_seconds
        self._batch_size = batch_size
        self._flush_interval_seconds = flush_interval_seconds

        self._lock = threading.Lock()
        self._pending = 0
        self._last_flush = time.monotonic()

    def store(self, ip: str, os_label: str) -> None:
        key = f"{self._key_prefix}{ip}"
        with self._lock:
            self._pipe.set(key, os_label, ex=self._ttl_seconds)
            self._pending += 1

            due = (
                self._pending >= self._batch_size
                or time.monotonic() - self._last_flush >= self._flush_interval_seconds
            )
            if due:
                self._flush_locked()

    def flush(self) -> None:
        """Flush any buffered writes now; safe to call on shutdown."""
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if self._pending:
            try:
                self._pipe.execute()
                log.debug("flushed %d entries", self._pending)
            except redis.RedisError as exc:
                # Best-effort: a lost batch just means those observations
                # are not cached; the next SYN from each client will retry.
                log.warning("flush of %d entries failed: %s", self._pending, exc)
                self._pipe.reset()
        self._pending = 0
        self._last_flush = time.monotonic()
