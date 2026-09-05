"""Entry point: sniff SYN packets, classify OS, write result to Redis."""
from . import _pcap_compat  # noqa: F401  (must run before any scapy import)

import logging
import signal

from scapy.sendrecv import AsyncSniffer
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from . import config, fingerprint, storage

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("pyp0f")


def handle_packet(packet) -> None:
    if "TCP" not in packet:
        return

    # p0f-style matching works on both address families; pick whichever
    # network-layer header is actually present on this packet.
    if IP in packet:
        src = packet[IP].src
    elif IPv6 in packet:
        src = packet[IPv6].src
    else:
        return

    os_label = fingerprint.classify(packet)
    if not os_label:
        return

    storage.store(src, os_label)


def main() -> None:
    log.info(
        "starting on iface=%s filter=%r db=%s",
        config.IFACE,
        config.BPF_FILTER,
        config.P0F_DB_PATH,
    )
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
        prn=handle_packet,
        store=False,
    )
    sniffer.start()

    def _shutdown(signum, _frame) -> None:
        log.info("shutting down (signal %s)", signum)
        sniffer.stop()
        storage.flush()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    sniffer.join()


if __name__ == "__main__":
    main()
