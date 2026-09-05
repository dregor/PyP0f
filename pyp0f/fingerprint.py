"""Thin wrapper around scapy's bundled p0f-compatible signature matcher.

conf.p0f_base must be set before scapy.modules.p0f is imported, since the
module loads its signature database once at import time into a module-level
object.
"""
from scapy.config import conf

from . import config

conf.p0f_base = config.P0F_DB_PATH

from scapy.modules.p0f import p0f  # noqa: E402  (import order matters, see above)


def classify(packet) -> str | None:
    """Return a human-readable OS label for a captured SYN packet, or None."""
    try:
        match = p0f(packet)
    except Exception:
        return None

    if not match:
        return None

    label = match[0]
    # label layout: (source, app/os marker, name, details[, sys_list])
    name, details = label[2], label[3]
    return f"{name} {details}".strip()
