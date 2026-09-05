"""Entry point: sniff SYN packets, classify OS, write result to Redis."""
import gc

# Disabled as early as possible, before the heavy scapy/p0f-database imports
# below run: with the collector off, loading them does not register their
# (large, long-lived, read-only once loaded) objects into a GC generation
# that a later collection cycle would otherwise walk - and, on the far side
# of a fork(), touch the refcount of and so needlessly copy-on-write. See
# main()/run_worker() for the other half of this (gc.freeze() and the
# per-worker gc.enable()) - the pattern is the one Instagram documented for
# their (also fork-based) application-server workers.
gc.disable()

from . import _pcap_compat  # noqa: F401  (must run before any scapy import)

import logging
import multiprocessing
import os
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


def shard_filter(base_filter: str, workers: int, index: int) -> str:
    """AND base_filter with a condition selecting ~1/workers of source IPs.

    Packet classification is plain Python and therefore single-core no
    matter the machine; running `workers` independent capture processes,
    each restricted (at the kernel/BPF level, before a packet ever reaches
    Python) to a disjoint slice of source addresses, is the only way to use
    more than one core for it.

    The split is on the low bits of the last address byte (source, checked
    for IPv4 and IPv6 separately since they're unrelated header layouts) -
    simple and even enough for load-splitting, but only correct for a
    power-of-2 worker count, since a bitmask can't otherwise divide the
    address space into equal, non-overlapping shares.
    """
    if workers <= 1:
        return base_filter
    if workers & (workers - 1) != 0:
        raise ValueError("workers must be a power of 2")

    mask = workers - 1
    shard = (
        f"((ip and (ip[15] & {mask}) = {index}) "
        f"or (ip6 and (ip6[23] & {mask}) = {index}))"
    )
    return f"({base_filter}) and {shard}"


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


def run_worker(index: int) -> None:
    """Capture and classify one shard of traffic; blocks until stopped."""
    # Undo the gc.disable() from module import time: freeze() in main() only
    # ever exempts objects that already existed at that point (the loaded
    # library/database) from future collection - everything a worker goes on
    # to allocate at runtime still needs normal generational GC to catch any
    # reference cycles, same as usual.
    gc.enable()

    bpf_filter = shard_filter(config.BPF_FILTER, config.WORKERS, index)
    log.info("worker %d starting on iface=%s filter=%r", index, config.IFACE, bpf_filter)

    # A RedisSink (and the connection it owns) must be created here, inside
    # the worker, not in the parent before forking - a connection made
    # before fork() would end up shared and corrupted across workers.
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
        filter=bpf_filter,
        prn=make_packet_handler(sink),
        store=False,
    )
    sniffer.start()

    shutdown = make_shutdown_handler(sniffer, sink)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    sniffer.join()


def main() -> None:
    log.info(
        "starting: workers=%d iface=%s db=%s",
        config.WORKERS,
        config.IFACE,
        config.P0F_DB_PATH,
    )

    # Load the signature database now, in this (pre-fork) process, so its
    # parsing happens once and every worker below shares the result via
    # copy-on-write rather than each re-loading its own private copy.
    fingerprint.preload()

    # Collect once to clear out anything already garbage from the imports
    # and the preload above, then exempt everything still alive (all of it
    # long-lived and read-only from here on) from future collection cycles.
    gc.collect()
    gc.freeze()

    if config.WORKERS <= 1:
        run_worker(0)
        return

    workers = [
        multiprocessing.Process(target=run_worker, args=(i,), name=f"pyp0f-worker-{i}")
        for i in range(config.WORKERS)
    ]
    for w in workers:
        w.start()

    def _shutdown_all(signum, _frame) -> None:
        log.info("shutting down (signal %s)", signum)
        # Forward the same signal so each worker's own handler flushes its
        # pending batch, rather than killing them outright.
        for w in workers:
            if w.pid:
                os.kill(w.pid, signum)
        for w in workers:
            w.join()

    signal.signal(signal.SIGTERM, _shutdown_all)
    signal.signal(signal.SIGINT, _shutdown_all)

    for w in workers:
        w.join()


if __name__ == "__main__":
    main()
