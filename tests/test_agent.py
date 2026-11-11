"""Regression tests for the audit fixes (no network, no real identity)."""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import technocore_agent as ta  # noqa: E402
import github_upload as gu  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


@pytest.fixture()
def pk():
    return Ed25519PrivateKey.generate()


def test_create_identity_confirms_passphrase(monkeypatch, tmp_path):
    calls = []
    answers = iter(["correct-horse-battery", "different-battery"])

    def fake_getpass(prompt=""):
        calls.append(prompt)
        return next(answers)

    monkeypatch.setattr(ta.getpass, "getpass", fake_getpass)
    with pytest.raises(ta.IdentityError, match="do not match"):
        ta.create_identity(tmp_path / "identity.pem")
    assert len(calls) == 2, f"confirm prompt never asked: {calls}"


def test_create_identity_rejects_short(monkeypatch, tmp_path):
    monkeypatch.setattr(ta.getpass, "getpass", lambda p="": "short")
    with pytest.raises(ta.IdentityError, match="at least 12"):
        ta.create_identity(tmp_path / "identity.pem")


def test_passphrase_keeps_surrounding_spaces(tmp_path):
    secret = "  spaced pass phrase  "
    path = tmp_path / "identity.pem"
    ta.create_identity(path, passphrase=secret)
    assert ta.load_identity(path, passphrase=secret) is not None
    with pytest.raises(Exception):
        ta.load_identity(path, passphrase=secret.strip())


def test_proof_v2_roundtrip(pk):
    proof = ta.contribution_proof(pk, "https://github.com/a/b", "a" * 40)
    assert proof["schema"] == ta.PROOF_SCHEMA_V2
    ta.verify_contribution_proof(proof)


def test_proof_v2_rejects_expired(pk, monkeypatch):
    past = int(time.time()) - 10_000
    monkeypatch.setattr(ta.time, "time", lambda: past)
    proof = ta.contribution_proof(pk, "https://github.com/a/b", "b" * 40, ttl_seconds=60)
    monkeypatch.undo()
    with pytest.raises(ta.ProtocolError, match="expired"):
        ta.verify_contribution_proof(proof)


def test_proof_v2_rejects_inverted_window(pk):
    proof = ta.contribution_proof(pk, "https://github.com/a/b", "b" * 40, ttl_seconds=-10)
    with pytest.raises(ta.ProtocolError, match="expires_at must be after"):
        ta.verify_contribution_proof(proof)


def test_proof_v2_rejects_userinfo_and_http(pk):
    with pytest.raises(ta.ProtocolError):
        ta.contribution_proof(pk, "https://user:pass@github.com/a/b", "c" * 40)
    with pytest.raises(ta.ProtocolError):
        ta.contribution_proof(pk, "http://github.com/a/b", "c" * 40)


def test_proof_rejects_unknown_schema(pk):
    proof = ta.contribution_proof(pk, "https://github.com/a/b", "d" * 40)
    proof["schema"] = "totally-evil-schema-v9"
    with pytest.raises(ta.ProtocolError, match="schema"):
        ta.verify_contribution_proof(proof)


def test_proof_v1_legacy_still_verifies(pk):
    did = ta.did_from_private_key(pk)
    payload = b"https://github.com/legacy/repo|" + b"e" * 40
    legacy = {
        "schema": ta.PROOF_SCHEMA_V1,
        "artifact_url": "https://github.com/legacy/repo",
        "commit": "e" * 40,
        "did": did,
        "signature": ta.sign_bytes(pk, payload),
    }
    ta.verify_contribution_proof(legacy)


def test_did_length_guard():
    start = time.time()
    with pytest.raises(ta.ProtocolError, match="too long"):
        ta.public_key_from_did("did:key:z" + "z" * 50000)
    assert time.time() - start < 1.0


def test_staged_secrets_detected(tmp_path):
    d = tmp_path / "up"
    d.mkdir()
    (d / "identity.pem").write_text("x")
    (d / "passphrase.txt").write_text("x")
    (d / "README.md").write_text("ok")
    subprocess.run(["git", "init", "-b", "main"], cwd=d, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=d, check=True, capture_output=True)
    bad = gu.staged_secrets(str(d))
    assert any("identity" in p for p in bad)
    assert any("passphrase" in p for p in bad)
    assert not any("README" in p for p in bad)
    with pytest.raises(RuntimeError, match="refusing to commit"):
        gu.guard_staged(str(d))


def test_redact_token():
    assert "ghp_" not in gu.redact("url https://x-access-token:ghp_abcdefgh12345678@github.com/a/b")
    assert "x-access" not in gu.redact("https://x-access-token:abc@github.com/a/b")
