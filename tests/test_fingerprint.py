from pyp0f import fingerprint


class _FakePacket:
    """Stand-in for a scapy Packet - only .summary() is used on the error path."""

    def summary(self) -> str:
        return "<fake packet>"


def _match(name: str, details: str):
    # (source, app/os marker, name, details[, sys_list]), dishonest
    return (("s", "!", name, details), False)


def test_classify_formats_name_and_details(monkeypatch):
    monkeypatch.setattr(fingerprint, "p0f", lambda pkt: _match("Linux", "2.2.x-3.x"))
    assert fingerprint.classify(_FakePacket()) == "Linux 2.2.x-3.x"


def test_classify_strips_trailing_space_when_details_empty(monkeypatch):
    monkeypatch.setattr(fingerprint, "p0f", lambda pkt: _match("Linux", ""))
    assert fingerprint.classify(_FakePacket()) == "Linux"


def test_classify_returns_none_on_no_match(monkeypatch):
    monkeypatch.setattr(fingerprint, "p0f", lambda pkt: None)
    assert fingerprint.classify(_FakePacket()) is None


def test_classify_returns_none_and_does_not_raise_on_error(monkeypatch):
    def _boom(pkt):
        raise ValueError("malformed signature")

    monkeypatch.setattr(fingerprint, "p0f", _boom)
    # A crafted/unusual packet must never take the whole process down over a
    # single failed classification.
    assert fingerprint.classify(_FakePacket()) is None
