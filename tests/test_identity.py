"""Identity handling: confirmation, passphrase files, encryption, overwrite."""
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import technocore_agent as ta


def test_create_identity_prompts_twice_and_confirms(tmp_path):
    path = tmp_path / "identity.pem"
    with mock.patch("technocore_agent.getpass.getpass",
                    side_effect=["correct-passphrase-1", "correct-passphrase-1"]) as gp:
        did = ta.create_identity(path=path, passphrase=None)
    assert gp.call_count == 2
    assert did.startswith("did:key:z")
    # The created key loads with the confirmed passphrase.
    ta.load_identity(path, passphrase="correct-passphrase-1")


def test_create_identity_mismatched_confirmation_refused(tmp_path):
    path = tmp_path / "identity.pem"
    with mock.patch("technocore_agent.getpass.getpass",
                    side_effect=["correct-passphrase-1", "typo-passphrase-12"]):
        with pytest.raises(ta.IdentityError, match="do not match"):
            ta.create_identity(path=path, passphrase=None)
    assert not path.exists()


def test_create_identity_short_passphrase_refused(tmp_path):
    with pytest.raises(ta.IdentityError, match="at least 12"):
        ta.create_identity(path=tmp_path / "identity.pem", passphrase="short")


def test_init_refuses_to_overwrite(tmp_path):
    path = tmp_path / "identity.pem"
    ta.create_identity(path=path, passphrase="dummy-passphrase-123")
    with pytest.raises(ta.IdentityError, match="already exists"):
        ta.create_identity(path=path, passphrase="other-passphrase-1")


def test_key_file_mode_0600(tmp_path):
    import os
    path = tmp_path / "identity.pem"
    ta.create_identity(path=path, passphrase="dummy-passphrase-123")
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_passphrase_with_leading_trailing_spaces_round_trips(tmp_path):
    # Audit PoC: .strip() silently broke "  spaced pass phrase  ".
    path = tmp_path / "identity.pem"
    spaced = "  spaced pass phrase  "
    ta.create_identity(path=path, passphrase=spaced)
    pf = tmp_path / "passphrase.txt"
    pf.write_text(spaced + "\n", encoding="utf-8")
    assert ta.read_passphrase_file(pf) == spaced
    ta.load_identity(path, passphrase=ta.read_passphrase_file(pf))


def test_passphrase_file_missing_is_clean_error(tmp_path):
    with pytest.raises(ta.IdentityError, match="cannot read passphrase file"):
        ta.read_passphrase_file(tmp_path / "nope.txt")


def test_wrong_passphrase_is_clean_identity_error(tmp_path):
    path = tmp_path / "identity.pem"
    ta.create_identity(path=path, passphrase="dummy-passphrase-123")
    with pytest.raises(ta.IdentityError, match="incorrect passphrase"):
        ta.load_identity(path, passphrase="wrong-passphrase-12")


def test_unencrypted_pem_refused(tmp_path):
    # Audit finding: an unencrypted PEM used to load silently.
    path = tmp_path / "identity.pem"
    pk = Ed25519PrivateKey.generate()
    raw = pk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path.write_bytes(raw)
    with pytest.raises(ta.IdentityError, match="NOT encrypted"):
        ta.load_identity(path, passphrase="whatever-passphrase")


def test_garbage_pem_is_clean_error(tmp_path):
    path = tmp_path / "identity.pem"
    path.write_bytes(b"this is not a PEM file")
    with pytest.raises(ta.IdentityError, match="not a valid PEM"):
        ta.load_identity(path, passphrase="whatever-passphrase")


def test_cli_errors_are_clean_not_tracebacks(tmp_path, capsys):
    # verify-proof on broken JSON, did on a missing key: exit 1, no traceback.
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert ta.main(["verify-proof", str(bad)]) == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err and err.startswith("error:")
    assert ta.main(["did", "--key", str(tmp_path / "missing.pem")]) == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err and err.startswith("error:")
