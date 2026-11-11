"""Proof v2: creation, verification, and every rejection the audit required."""
import copy
import time

import pytest

import technocore_agent as ta

URL = "https://github.com/zannyzette/technocore-did-gameplay"
COMMIT = "a" * 40


@pytest.fixture()
def key(tmp_path):
    path = tmp_path / "identity.pem"
    ta.create_identity(path=path, passphrase="dummy-passphrase-123")
    return ta.load_identity(path, passphrase="dummy-passphrase-123")


def test_valid_proof_verifies(key):
    proof = ta.contribution_proof(key, URL, COMMIT)
    assert proof["schema"] == "technocore-contribution-proof-v2"
    assert proof["issued_at"] <= int(time.time())
    assert proof["expires_at"] > proof["issued_at"]
    ta.verify_contribution_proof(proof)  # must not raise


def test_two_proofs_never_share_a_nonce(key):
    p1 = ta.contribution_proof(key, URL, COMMIT)
    p2 = ta.contribution_proof(key, URL, COMMIT)
    assert p1["nonce"] != p2["nonce"]
    assert p1["signature"] != p2["signature"]
    ta.verify_contribution_proof(p1)
    ta.verify_contribution_proof(p2)


def test_v1_proof_rejected(key):
    # The old v1 shape: no issued_at/expires_at/nonce, schema v1.
    old = {
        "schema": "technocore-contribution-proof-v1",
        "artifact_url": URL,
        "commit": COMMIT,
        "did": ta.did_from_private_key(key),
        "signature": ta.sign_bytes(key, f"{URL}|{COMMIT}".encode()),
    }
    with pytest.raises(ta.ProtocolError, match="unsupported proof schema"):
        ta.verify_contribution_proof(old)


def test_missing_schema_rejected(key):
    proof = ta.contribution_proof(key, URL, COMMIT)
    del proof["schema"]
    with pytest.raises(ta.ProtocolError, match="missing field: schema"):
        ta.verify_contribution_proof(proof)


def test_evil_schema_rejected(key):
    proof = ta.contribution_proof(key, URL, COMMIT)
    proof["schema"] = "totally-evil-schema-v9"
    with pytest.raises(ta.ProtocolError, match="unsupported proof schema"):
        ta.verify_contribution_proof(proof)


@pytest.mark.parametrize("bad_url", [
    "http://github.com/zannyzette/technocore-did-gameplay",   # http, not https
    "ftp://evil.example/x",
    "http://evil.example/pwn",
    "https://user:pass@github.com/a/b",                      # userinfo
    "https://evil.example/x",                                # host not allowlisted
    "https://github.com/a/b\ninjected",                      # newline
    "HTTPS://github.com/a/b",                                # scheme case
])
def test_bad_artifact_url_rejected_at_creation(key, bad_url):
    with pytest.raises(ta.ProtocolError):
        ta.contribution_proof(key, bad_url, COMMIT)


def test_replay_after_expiry_rejected(key):
    # A proof whose expiry is in the past must not verify (audit PoC: the
    # repo's old proof.json stayed valid forever).
    proof = ta.contribution_proof(
        key, URL, COMMIT,
        issued_at=int(time.time()) - 10_000,
        expires_at=int(time.time()) - 100,
    )
    with pytest.raises(ta.ProtocolError, match="expired"):
        ta.verify_contribution_proof(proof)


def test_tampered_commit_rejected(key):
    proof = ta.contribution_proof(key, URL, COMMIT)
    proof["commit"] = "b" * 40
    with pytest.raises(ta.IdentityError):
        ta.verify_contribution_proof(proof)


def test_tampered_url_rejected(key):
    # The audit's linux-claim PoC: signing a stranger's URL must not verify
    # as this repo's proof once the URL is swapped.
    proof = ta.contribution_proof(key, URL, COMMIT)
    proof["artifact_url"] = "https://github.com/torvalds/linux"
    with pytest.raises(ta.IdentityError):
        ta.verify_contribution_proof(proof)


def test_short_and_garbage_signatures_rejected(key):
    proof = ta.contribution_proof(key, URL, COMMIT)
    for bad_sig in ["A", "AAAAA", "A" * 85, "!!!not-base64!!!", "A" * 86 + "=="]:
        bad = copy.deepcopy(proof)
        bad["signature"] = bad_sig
        with pytest.raises((ta.ProtocolError, ta.IdentityError)):
            ta.verify_contribution_proof(bad)


def test_rotation_round_trip(tmp_path):
    old_path = tmp_path / "old.pem"
    new_path = tmp_path / "new.pem"
    ta.create_identity(path=old_path, passphrase="old-passphrase-123")
    ta.create_identity(path=new_path, passphrase="new-passphrase-123")
    old_pk = ta.load_identity(old_path, passphrase="old-passphrase-123")
    new_pk = ta.load_identity(new_path, passphrase="new-passphrase-123")
    stmt = ta.rotation_statement(old_pk, ta.did_from_private_key(new_pk))
    ta.verify_rotation_statement(stmt)
    # Tamper: point the rotation at a third DID — must fail.
    third = tmp_path / "third.pem"
    ta.create_identity(path=third, passphrase="third-passphrase-1")
    third_pk = ta.load_identity(third, passphrase="third-passphrase-1")
    bad = copy.deepcopy(stmt)
    bad["did"] = ta.did_from_private_key(third_pk)
    with pytest.raises(ta.IdentityError):
        ta.verify_rotation_statement(bad)


def test_revocation_round_trip(tmp_path):
    path = tmp_path / "identity.pem"
    ta.create_identity(path=path, passphrase="dummy-passphrase-123")
    pk = ta.load_identity(path, passphrase="dummy-passphrase-123")
    stmt = ta.revocation_statement(pk, "key may be compromised")
    ta.verify_revocation_statement(stmt)
    bad = copy.deepcopy(stmt)
    bad["reason"] = "different reason"
    with pytest.raises(ta.IdentityError):
        ta.verify_revocation_statement(bad)
