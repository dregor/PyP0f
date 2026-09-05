"""Thin wrapper around scapy's bundled p0f-compatible signature matcher."""
import logging

from scapy.config import conf

from . import config

import scapy.modules.p0f as _p0f_module

log = logging.getLogger("pyp0f.fingerprint")

# scapy.modules.p0f unconditionally sets conf.p0f_base to a default system
# path (and builds its knowledge base from it) as a side effect of being
# imported, so the database has to be reloaded again afterwards rather than
# configured beforehand.
conf.p0f_base = config.P0F_DB_PATH
_p0f_module.p0fdb = _p0f_module.p0fKnowledgeBase(config.P0F_DB_PATH)

p0f = _p0f_module.p0f


def preload() -> None:
    """Force the (otherwise lazily-loaded on first use) database to load now.

    Meant to be called once, before forking worker processes: the database
    is parsed a single time and the result then shared with every worker via
    copy-on-write, instead of each one independently loading and parsing its
    own private copy after fork.
    """
    _p0f_module.p0fdb.get_base()


def classify(packet) -> str | None:
    """Return a human-readable OS label for a captured SYN packet, or None."""
    try:
        match = p0f(packet)
    except Exception as exc:
        log.debug("p0f matching raised %r for packet %s", exc, packet.summary())
        return None

    if not match:
        return None

    label = match[0]
    # label layout: (source, app/os marker, name, details[, sys_list])
    name, details = label[2], label[3]
    return f"{name} {details}".strip()
