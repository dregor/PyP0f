from unittest.mock import Mock

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

from pyp0f import main as main_module
from pyp0f.main import make_packet_handler, make_shutdown_handler, packet_source_ip


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
