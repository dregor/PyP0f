"""Entry point: sniff SYN packets, classify OS, write result to Redis."""
import logging

from scapy.all import sniff

from . import config, fingerprint, storage

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("pyp0f")


def handle_packet(packet) -> None:
    if "IP" not in packet or "TCP" not in packet:
        return

    os_label = fingerprint.classify(packet)
    if not os_label:
        return

    storage.store(packet["IP"].src, os_label)


def main() -> None:
    log.info(
        "starting on iface=%s filter=%r db=%s",
        config.IFACE,
        config.BPF_FILTER,
        config.P0F_DB_PATH,
    )
    # store=False is essential for a long-running process: by default scapy
    # keeps every captured packet in memory for the lifetime of the sniff()
    # call, which would grow without bound here.
    sniff(
        iface=config.IFACE,
        filter=config.BPF_FILTER,
        prn=handle_packet,
        store=False,
    )


if __name__ == "__main__":
    main()
