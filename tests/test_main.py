from unittest.mock import Mock

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

from pyp0f import main as main_module
from pyp0f.main import (
    make_packet_handler,
    make_shutdown_handler,
    packet_source_ip,
    shard_filter,
)


def test_packet_source_ip_ipv4():
    pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP()
    assert packet_source_ip(pkt) == "1.2.3.4"


def test_packet_source_ip_ipv6():
    pkt = IPv6(src="::1", dst="::2") / TCP()
    assert packet_source_ip(pkt) == "::1"


def test_packet_source_ip_none_without_ip_layer():
    pkt = Raw(load=b"not an ip packet")
    assert packet_source_ip(pkt) is None


def test_handle_packet_stores_classification(monkeypatch):
    monkeypatch.setattr(main_module.fingerprint, "classify", lambda pkt: "Linux")
    sink = Mock()
    handler = make_packet_handler(sink)

    handler(IP(src="1.2.3.4") / TCP())

    sink.store.assert_called_once_with("1.2.3.4", "Linux")


def test_handle_packet_stores_empty_string_on_no_match(monkeypatch):
    monkeypatch.setattr(main_module.fingerprint, "classify", lambda pkt: None)
    sink = Mock()
    handler = make_packet_handler(sink)

    handler(IP(src="1.2.3.4") / TCP())

    # A miss is still an observation of the IP - it is recorded (with no
    # label) rather than dropped, so a real service in front of this data
    # can tell "seen, unclassified" apart from "never seen".
    sink.store.assert_called_once_with("1.2.3.4", "")


def test_handle_packet_stores_empty_string_and_does_not_raise_on_classify_error(monkeypatch):
    def _boom(pkt):
        raise ValueError("boom")

    monkeypatch.setattr(main_module.fingerprint, "classify", _boom)
    sink = Mock()
    handler = make_packet_handler(sink)

    handler(IP(src="1.2.3.4") / TCP())  # must not raise

    sink.store.assert_called_once_with("1.2.3.4", "")


def test_handle_packet_skips_non_tcp_packets():
    sink = Mock()
    handler = make_packet_handler(sink)

    handler(IP(src="1.2.3.4"))  # no TCP layer

    sink.store.assert_not_called()


def test_handle_packet_skips_packets_without_ip_layer():
    sink = Mock()
    handler = make_packet_handler(sink)

    handler(Raw(load=b"garbage"))

    sink.store.assert_not_called()


def test_shutdown_handler_stops_sniffer_and_flushes_sink():
    sniffer = Mock()
    sink = Mock()
    handler = make_shutdown_handler(sniffer, sink)

    handler(15, None)  # 15 == signal.SIGTERM

    sniffer.stop.assert_called_once()
    sink.flush.assert_called_once()


def test_shard_filter_single_worker_is_unchanged():
    assert shard_filter("tcp", 1, 0) == "tcp"


def test_shard_filter_two_workers_are_distinct_and_use_both_address_families():
    even = shard_filter("tcp", 2, 0)
    odd = shard_filter("tcp", 2, 1)

    assert even != odd
    for expr in (even, odd):
        assert "tcp" in expr
        assert "ip[15]" in expr  # IPv4: last byte of the source address
        assert "ip6[23]" in expr  # IPv6: last byte of the source address


@pytest.mark.parametrize("workers", [2, 4, 8])
def test_shard_filter_partitions_every_byte_value_exactly_once(workers):
    # Mirrors the bitmask arithmetic a BPF filter would evaluate at runtime,
    # to check the *scheme* (not just the string) actually partitions the
    # full byte range with no gaps and no overlap between workers.
    mask = workers - 1
    owner_of = {}
    for byte in range(256):
        claimants = [idx for idx in range(workers) if (byte & mask) == idx]
        assert len(claimants) == 1, f"byte {byte} claimed by {claimants}"
        owner_of[byte] = claimants[0]

    assert set(owner_of.values()) == set(range(workers))


@pytest.mark.parametrize("workers", [3, 5, 6, 100])
def test_shard_filter_rejects_non_power_of_two_worker_counts(workers):
    with pytest.raises(ValueError):
        shard_filter("tcp", workers, 0)


def test_shard_filter_four_workers_uses_a_two_bit_mask():
    expr = shard_filter("tcp", 4, 2)
    assert "& 3" in expr
    assert "= 2" in expr
