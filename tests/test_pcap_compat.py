import ctypes.util

from pyp0f import _pcap_compat


def test_find_library_patch_is_installed():
    assert ctypes.util.find_library is _pcap_compat._find_library


def test_find_library_passes_through_a_real_result(monkeypatch):
    monkeypatch.setattr(_pcap_compat, "_original_find_library", lambda name: f"real-{name}.so")
    assert _pcap_compat._find_library("pcap") == "real-pcap.so"


def test_find_library_falls_back_when_original_finds_nothing(monkeypatch):
    # This is the actual musl/Alpine failure mode this module works around:
    # ctypes.util.find_library() returns None even though the library is
    # installed, because it relies on ldconfig's cache, which musl doesn't
    # provide.
    monkeypatch.setattr(_pcap_compat, "_original_find_library", lambda name: None)
    assert _pcap_compat._find_library("pcap") == "libpcap.so"
