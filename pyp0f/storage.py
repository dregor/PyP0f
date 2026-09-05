"""Write-only Redis sink: IP -> OS label, with a TTL.

No local state is kept in this process on purpose - every observation is
handed off to Redis immediately, so the process itself stays effectively
stateless and memory usage does not grow over time.
"""
import redis

from . import config

_client = redis.Redis(
    host=config.REDIS_HOST,
    port=config.REDIS_PORT,
    db=config.REDIS_DB,
    socket_timeout=1,
    socket_connect_timeout=1,
)


def store(ip: str, os_label: str) -> None:
    key = f"{config.REDIS_KEY_PREFIX}{ip}"
    try:
        _client.set(key, os_label, ex=config.REDIS_TTL_SECONDS)
    except redis.RedisError:
        # Best-effort: a lost write just means this particular observation
        # is not cached; the next SYN from the same client will retry.
        pass
