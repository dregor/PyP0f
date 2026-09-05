"""Work around ctypes.util.find_library() failing on musl/Alpine.

On glibc systems it shells out to ldconfig's cache to locate a shared
library by its short name; musl-based systems (e.g. Alpine) don't ship an
equivalent cache, so the lookup returns None even when the library is
installed and would load fine via a plain dlopen() of its usual name.
scapy relies on find_library("pcap") to locate libpcap, so this has to be
patched before scapy (specifically scapy.libs.winpcapy) is imported.
"""
import ctypes.util

_original_find_library = ctypes.util.find_library


def _find_library(name: str):
    return _original_find_library(name) or f"lib{name}.so"


ctypes.util.find_library = _find_library
