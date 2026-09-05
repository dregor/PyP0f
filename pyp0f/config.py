"""Configuration loaded entirely from environment variables."""
import os


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


# Network interface to listen on.
IFACE = _env("PYP0F_IFACE", "eth0")

# Only new TCP connections (SYN, not SYN-ACK) are needed for classification,
# so the filter is narrowed at the kernel (BPF) level rather than in Python.
BPF_FILTER = _env(
    "PYP0F_BPF_FILTER",
    "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 "
    "and (port 80 or port 443)",
)

# Path to the p0f.fp signature database (p0f v3 format).
P0F_DB_PATH = _env("PYP0F_DB_PATH", "/app/p0f.fp")

REDIS_HOST = _env("PYP0F_REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(_env("PYP0F_REDIS_PORT", "6379"))
REDIS_DB = int(_env("PYP0F_REDIS_DB", "0"))
REDIS_KEY_PREFIX = _env("PYP0F_REDIS_KEY_PREFIX", "pyp0f:")
REDIS_TTL_SECONDS = int(_env("PYP0F_REDIS_TTL_SECONDS", str(120 * 60)))

# Writes are pipelined and flushed once BATCH_SIZE observations have piled up
# or FLUSH_INTERVAL_SECONDS have passed since the last flush, whichever comes
# first (the latter bounds staleness at low traffic volumes).
REDIS_BATCH_SIZE = int(_env("PYP0F_REDIS_BATCH_SIZE", "50"))
REDIS_FLUSH_INTERVAL_SECONDS = float(_env("PYP0F_REDIS_FLUSH_INTERVAL_SECONDS", "1"))
