"""Entry point: sniff SYN packets, classify OS, write result to Redis."""
from . import _pcap_compat  # noqa: F401  (must run before any scapy import)

import logging
import signal
from typing import Callable

from scapy.sendrecv import AsyncSniffer
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from . import config, fingerprint
from .storage import RedisSink

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("pyp0f")


def packet_source_ip(packet) -> str | None:
    """Return the packet's source address, IPv4 or IPv6, or None for neither."""
    if IP in packet:
        return packet[IP].src
    if IPv6 in packet:
        return packet[IPv6].src
    return None


def make_packet_handler(sink: RedisSink) -> Callable:
    def handle_packet(packet) -> None:
        if "TCP" not in packet:
            return

        src = packet_source_ip(packet)
        if src is None:
            log.debug("skipped: no IPv4/IPv6 layer")
            return

        # fingerprint.classify() already contains its own errors, but this is
        # a long-running per-packet callback: nothing about a single bad or
        # unusual packet should ever be allowed to take the capture loop
        # down. A failure here is recorded the same way a clean no-match is -
        # the IP was seen, just with no OS label - rather than silently
        # dropping the observation entirely.
        try:
            os_label = fingerprint.classify(packet) or ""
        except Exception as exc:
            log.error("unexpected error classifying %s: %s", src, exc)
            os_label = ""

        if os_label:
            log.debug("classified %s as %r", src, os_label)
        else:
            log.debug("no match: %s", src)

        sink.store(src, os_label)

    return handle_packet


def make_shutdown_handler(sniffer: AsyncSniffer, sink: RedisSink) -> Callable:
    def _shutdown(signum, _frame) -> None:
        log.info("shutting down (signal %s)", signum)
        sniffer.stop()
        sink.flush()

    return _shutdown


def main() -> None:
    log.info(
        "starting on iface=%s filter=%r db=%s",
        config.IFACE,
        config.BPF_FILTER,
        config.P0F_DB_PATH,
    )
    sink = RedisSink()

    # store=False is essential for a long-running process: by default scapy
    # keeps every captured packet in memory for the lifetime of the sniff
    # session, which would grow without bound here.
    #
    # sniff() itself is a thin blocking wrapper around AsyncSniffer; using it
    # directly means a stop signal (e.g. `docker stop`, which sends SIGTERM)
    # can flush the last pending batch of writes instead of dropping it.
    sniffer = AsyncSniffer(
        iface=config.IFACE,
        filter=config.BPF_FILTER,
        prn=make_packet_handler(sink),
        store=False,
    )
    sniffer.start()

    shutdown = make_shutdown_handler(sniffer, sink)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    sniffer.join()


if __name__ == "__main__":
    main()
