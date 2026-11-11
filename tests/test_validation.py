"""Validation & DoS guards: messages, room params, DID length, signatures."""
import time

import pytest

import technocore_agent as ta


def test_normalize_message_rejects_invisible_only():
    with pytest.raises(ta.ProtocolError, match="no visible text"):
        ta.normalize_message("​\u200b\ufeff")


def test_normalize_message_replaces_invisible_with_space():
    assert ta.normalize_message("a\u200bb") == "a b"


def test_normalize_message_too_long():
    with pytest.raises(ta.ProtocolError, match="too long"):
        ta.normalize_message("x" * 4097)


def test_validate_name_rejects_bad_rooms():
    for bad in ["Lobby", "UPPER", "has space", "a" * 49, "", "-lead", "UP"]:
        with pytest.raises(ta.ProtocolError):
            ta.validate_name(bad)


def test_read_room_validates_limit_and_since(monkeypatch):
    seen = {}

    def fake_request(path, body=None):
        seen["path"] = path
        return {}

    monkeypatch.setattr(ta, "_request", fake_request)
    ta.read_room("lobby", limit=200)
    assert "limit=200" in seen["path"]
    for bad_limit in [0, -5, 201, 10_000]:
        with pytest.raises(ta.ProtocolError, match="limit must be between"):
            ta.read_room("lobby", limit=bad_limit)
    with pytest.raises(ta.ProtocolError, match="since must be"):
        ta.read_room("lobby", since=-1)


def test_giant_did_rejected_fast():
    # Audit PoC: 50k chars took ~0.7s (quadratic). Must now fail fast.
    start = time.monotonic()
    with pytest.raises(ta.ProtocolError, match="too long"):
        ta.public_key_from_did("did:key:z" + "z" * 50_000)
    assert time.monotonic() - start < 0.5


def test_decode_signature_rejects_garbage():
    for bad in ["!!!not-base64!!!", "A", "A" * 85, "A" * 87]:
        with pytest.raises(ta.ProtocolError):
            ta.decode_signature(bad)
    # A real 86-char signature decodes to 64 bytes.
    import base64
    sig = base64.urlsafe_b64encode(b"\x00" * 64).decode().rstrip("=")
    assert len(sig) == 86
    assert ta.decode_signature(sig) == b"\x00" * 64
