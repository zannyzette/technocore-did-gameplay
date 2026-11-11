"""Tests for the 7 gaps found in the v1.2.0 patch review (2026-11-12)."""
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

import github_upload as gu
import technocore_agent as ta


# --- 1. init must refuse to create a SECOND identity -----------------------

def test_init_refuses_when_identity_already_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(ta, "KEY_PATH", tmp_path / "home" / "identity.pem")
    monkeypatch.setattr(ta, "LEGACY_KEY_PATH", tmp_path / "cwd" / "identity.pem")
    ta.KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    ta.create_identity(path=ta.KEY_PATH, passphrase="dummy-passphrase-123")

    pf = tmp_path / "pp.txt"
    pf.write_text("dummy-passphrase-123\n", encoding="utf-8")
    rc = ta.main(["init", "--passphrase-file", str(pf)])
    assert rc == 1  # refused, did not silently mint a second DID


def test_init_refuses_when_legacy_identity_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(ta, "KEY_PATH", tmp_path / "home" / "identity.pem")
    monkeypatch.setattr(ta, "LEGACY_KEY_PATH", tmp_path / "cwd" / "identity.pem")
    ta.LEGACY_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    ta.create_identity(path=ta.LEGACY_KEY_PATH, passphrase="dummy-passphrase-123")

    pf = tmp_path / "pp.txt"
    pf.write_text("dummy-passphrase-123\n", encoding="utf-8")
    rc = ta.main(["init", "--passphrase-file", str(pf)])
    assert rc == 1
    # The canonical path must NOT have been created behind the user's back.
    assert not ta.KEY_PATH.exists()


def test_init_works_when_no_identity_anywhere(tmp_path, monkeypatch):
    monkeypatch.setattr(ta, "KEY_PATH", tmp_path / "home" / "identity.pem")
    monkeypatch.setattr(ta, "LEGACY_KEY_PATH", tmp_path / "cwd" / "identity.pem")
    pf = tmp_path / "pp.txt"
    pf.write_text("dummy-passphrase-123\n", encoding="utf-8")
    assert ta.main(["init", "--passphrase-file", str(pf)]) == 0
    assert ta.KEY_PATH.exists()


# --- 2. templates and public halves must not be blocked --------------------

@pytest.mark.parametrize("relpath", [
    ".env.example", ".env.sample", ".env.template", ".env.dist",
    "docs/.env.example", "id_rsa.pub", "id_ed25519.pub",
    "credentials.example", "config.json", "README.md", "proof.json",
])
def test_public_files_allowed(relpath):
    assert gu.is_secret_path(relpath) is False


@pytest.mark.parametrize("relpath", [
    "credentials.json", "credentials.yaml", "credentials.yml",
    "wallet.json", "keystore.json", "seed.txt", "seedphrase.txt",
    "deploy_key", ".npmrc", ".pypirc", ".netrc", "foo.p12", "foo.pfx",
    ".gnupg/private-keys-v1.d/x.key",
])
def test_newly_blocked_secrets(relpath):
    assert gu.is_secret_path(relpath) is True


def test_upload_dir_with_env_example_is_allowed(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / "README.md").write_text("hi\n", encoding="utf-8")
    (work / ".env.example").write_text("API_KEY=changeme\n", encoding="utf-8")
    gu.stage_and_commit(str(work), "demo", "main")  # must not raise
    r = subprocess.run(["git", "ls-files"], cwd=str(work), capture_output=True, text=True)
    assert ".env.example" in r.stdout


def test_protective_gitignore_keeps_templates_trackable(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / "README.md").write_text("hi\n", encoding="utf-8")
    (work / ".env.example").write_text("X=1\n", encoding="utf-8")
    gu.ensure_protective_gitignore(str(work))
    r = subprocess.run(["git", "check-ignore", "-v", ".env.example"],
                       cwd=str(work), capture_output=True, text=True)
    assert r.returncode != 0, ".env.example must not be ignored"


# --- 3. rotation.json / revocation.json must be committable ----------------

def test_rotation_json_not_gitignored():
    repo_root = Path(__file__).resolve().parents[1]
    text = (repo_root / ".gitignore").read_text(encoding="utf-8")
    active = [ln.strip() for ln in text.splitlines()
              if ln.strip() and not ln.strip().startswith("#")]
    assert "rotation.json" not in active
    assert "revocation.json" not in active


# --- 4. proof URL allowlist covers what README promises -------------------

@pytest.mark.parametrize("url", [
    "https://github.com/a/b",
    "https://gist.github.com/a/b",
    "https://gitlab.com/a/b",
    "https://medium.com/@me/post",
    "https://youtube.com/watch?v=x",
    "https://dev.to/me/post",
    "https://mirror.xyz/me/post",
])
def test_allowed_proof_hosts(url):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    pk = Ed25519PrivateKey.generate()
    proof = ta.contribution_proof(pk, url, "a" * 40)
    ta.verify_contribution_proof(proof)


def test_env_var_extends_proof_hosts(monkeypatch):
    import importlib
    monkeypatch.setenv("TECHNOCORE_PROOF_HOSTS", "blog.example.org")
    mod = importlib.reload(ta)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        pk = Ed25519PrivateKey.generate()
        proof = mod.contribution_proof(pk, "https://blog.example.org/post", "a" * 40)
        mod.verify_contribution_proof(proof)
    finally:
        monkeypatch.delenv("TECHNOCORE_PROOF_HOSTS", raising=False)
        importlib.reload(mod)


def test_unknown_host_still_rejected():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    pk = Ed25519PrivateKey.generate()
    with pytest.raises(ta.ProtocolError, match="allowlist"):
        ta.contribution_proof(pk, "https://evil.example/x", "a" * 40)


# --- 5. proof nonce accepts hex AND base64url (cross-implementation) ------

def test_base64url_nonce_verifies():
    import base64
    import time as _t
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    pk = Ed25519PrivateKey.generate()
    url, commit = "https://github.com/a/b", "a" * 40
    nonce = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
    now = int(_t.time())
    proof = ta.contribution_proof(pk, url, commit, issued_at=now,
                                 expires_at=now + 3600, nonce=nonce)
    assert proof["nonce"] == nonce
    ta.verify_contribution_proof(proof)


def test_hex_nonce_still_verifies():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    pk = Ed25519PrivateKey.generate()
    proof = ta.contribution_proof(pk, "https://github.com/a/b", "a" * 40)
    assert all(c in "0123456789abcdef" for c in proof["nonce"])
    ta.verify_contribution_proof(proof)


def test_short_or_garbage_nonce_rejected():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    pk = Ed25519PrivateKey.generate()
    for bad in ["short", "x" * 200, "has space in it 1234"]:
        with pytest.raises(ta.ProtocolError):
            ta.contribution_proof(pk, "https://github.com/a/b", "a" * 40, nonce=bad)
