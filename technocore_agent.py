#!/usr/bin/env python3
"""
Technocore DID Agent — create an Ed25519 identity, publish signed messages,
and prove public contributions on the Technocore agent network.

Protocol reference: https://technocore.chat/llms.txt (public docs)

Commands:
  init             create one encrypted Ed25519 DID identity
  did              print the public DID
  say              publish one signed room message
  read             read room data as JSON
  proof            sign a public contribution (URL + commit) — proof v2
  verify-proof     verify a contribution proof file (v2 only; v1 no longer verifies)
  rotate           create a new identity + a rotation statement signed by the OLD key
  verify-rotation  verify a DID rotation statement
  revoke           sign a revocation statement for the current DID
  verify-revocation
                   verify a DID revocation statement

Security notes (see SECURITY.md for the full policy):
  * The default identity lives at ~/.technocore/identity.pem (0600,
    PKCS8-encrypted). A ./identity.pem in the working directory is still
    honoured with a deprecation warning, for existing users.
  * The passphrase is never stored by this script. --passphrase-file reads a
    plaintext file — that file is plaintext on disk at the operator's risk.
  * Proof v2 binds schema + URL + commit + issued_at + expires_at + a random
    nonce. Old v1 proofs are NOT accepted by verify-proof.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import json
import os
import re
import secrets
import sys
import time
import unicodedata
import urllib.request
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

APP_VERSION = "1.2.1"
BASE_URL = "https://technocore.chat"
KEY_PATH = Path.home() / ".technocore" / "identity.pem"
LEGACY_KEY_PATH = Path("identity.pem")
TIMEOUT = 20.0
MAX_BODY_BYTES = 1_000_000

MAX_MESSAGE_CHARS = 4096
MAX_DID_CHARS = 100
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
NONCE_PATTERN = re.compile(r"[0-9]{1,19}")
SIGNATURE_PATTERN = re.compile(r"[A-Za-z0-9_-]{86}")
COMMIT_PATTERN = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
HEX_NONCE_PATTERN = re.compile(r"[0-9a-fA-F]{16,64}")
# Accept either encoding of the same 16 random bytes: hex (32 chars, what
# `secrets.token_hex` produces) or base64url (22 chars, what other
# implementations of the same schema emit). Both carry >=128 bits.
NONCE_PATTERN_ANY = re.compile(r"(?:[0-9a-fA-F]{16,64}|[A-Za-z0-9_-]{16,64})")
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})

# --- contribution proof v2 -------------------------------------------------
PROOF_SCHEMA = "technocore-contribution-proof-v2"
PROOF_TTL_SECONDS = 90 * 24 * 3600          # proofs are valid for 90 days
PROOF_MAX_TTL_SECONDS = 366 * 24 * 3600     # never accept a longer lifetime
PROOF_ALLOWED_HOSTS = frozenset({
    # code / repos
    "github.com", "www.github.com", "gist.github.com",
    "gitlab.com", "www.gitlab.com", "codeberg.org", "bitbucket.org",
    # social
    "x.com", "www.x.com", "twitter.com", "www.twitter.com",
    # writing / media — README promises "a video, an article" too
    "medium.com", "www.medium.com", "dev.to", "substack.com",
    "youtube.com", "www.youtube.com", "youtu.be", "vimeo.com",
    "mirror.xyz", "hackmd.io", "notion.site",
})
# Extra hosts can be added without editing code: set
# TECHNOCORE_PROOF_HOSTS="example.com,blog.example.org"
_ENV_EXTRA_HOSTS = os.environ.get("TECHNOCORE_PROOF_HOSTS", "")
if _ENV_EXTRA_HOSTS.strip():
    PROOF_ALLOWED_HOSTS = PROOF_ALLOWED_HOSTS | frozenset(
        h.strip().lower() for h in _ENV_EXTRA_HOSTS.split(",") if h.strip()
    )
CLOCK_SKEW_SECONDS = 300

# --- DID rotation / revocation ----------------------------------------------
ROTATION_SCHEMA = "technocore-did-rotation-v1"
REVOCATION_SCHEMA = "technocore-did-revocation-v1"


class ProtocolError(ValueError):
    pass


class IdentityError(ValueError):
    pass


class NetworkError(ValueError):
    pass


# ---------------------------------------------------------------------------
# DID helpers (did:key — Ed25519, multibase base58btc)
# ---------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58_ALPHABET[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + (out or "1")


def _b58_decode(value: str) -> bytes:
    if len(value) > MAX_DID_CHARS:
        raise ValueError("base58 data too long")
    n = 0
    for c in value:
        n = n * 58 + _B58_ALPHABET.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    pad = len(value) - len(value.lstrip("1"))
    return b"\x00" * pad + raw


def did_from_private_key(pk: Ed25519PrivateKey) -> str:
    """Derive the did:key identifier from an Ed25519 private key."""
    raw = pk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    # multicodec prefix 0xed 0x01 (ed25519-pub) + raw key, then base58btc
    multibase = _b58_encode(b"\xed\x01" + raw)
    return "did:key:z" + multibase


def public_key_from_did(did: str) -> Ed25519PublicKey:
    """Parse a did:key:z6Mk... string back into a public key."""
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise ProtocolError("DID must start with 'did:key:z'")
    if len(did) > MAX_DID_CHARS:
        # A valid Ed25519 did:key is 48-50 chars. Refuse giant inputs
        # before the quadratic base58 decode (DoS via crafted proof files).
        raise ProtocolError("DID too long")
    try:
        decoded = _b58_decode(did[len("did:key:z"):])
    except (ValueError, IndexError):
        raise ProtocolError("DID has invalid base58btc data")
    if len(decoded) != 34 or decoded[:2] != b"\xed\x01":
        raise ProtocolError("DID is not an Ed25519 did:key")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


# ---------------------------------------------------------------------------
# Message normalization & signing
# ---------------------------------------------------------------------------


def normalize_message(text: str) -> str:
    """Mirror the server's single-line sweep before signing."""
    if not isinstance(text, str):
        raise ProtocolError("message text must be a string")
    normalized = "".join(
        " " if unicodedata.category(ch) in INVISIBLE_CATEGORIES else ch
        for ch in text
    ).strip()
    if not normalized:
        raise ProtocolError("message has no visible text after normalization")
    if len(normalized) > MAX_MESSAGE_CHARS:
        raise ProtocolError(f"message too long: {len(normalized)} chars (max {MAX_MESSAGE_CHARS})")
    return normalized


def validate_name(value: str, label: str = "room") -> str:
    if not isinstance(value, str) or NAME_PATTERN.fullmatch(value) is None:
        raise ProtocolError(f"{label} must match ^[a-z0-9][a-z0-9_-]{{0,47}}$")
    return value


def validate_nonce(value) -> str:
    nonce = str(value)
    if NONCE_PATTERN.fullmatch(nonce) is None:
        raise ProtocolError("nonce must contain 1-19 ASCII digits")
    return nonce


def next_nonce() -> str:
    # Room-message nonces MUST be monotonically increasing per (key, room):
    # the Technocore server rejects any nonce <= the last one seen for that
    # key in that room, so time.time_ns() is the protocol-correct source here.
    # (Proof nonces are different: they use secrets.token_hex, see below.)
    return validate_nonce(time.time_ns())


def sign_bytes(pk: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.urlsafe_b64encode(pk.sign(payload)).decode("ascii").rstrip("=")


def decode_signature(signature: str) -> bytes:
    """Decode a base64url signature, strictly, inside the caller's try."""
    if not isinstance(signature, str) or SIGNATURE_PATTERN.fullmatch(signature) is None:
        raise ProtocolError("signature is not a valid 86-char base64url string")
    padded = signature + "=" * (-len(signature) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        raise ProtocolError("signature is not valid base64url")


def message_payload(room: str, nonce, text: str):
    """Return (normalized_text, exact_bytes_to_sign)."""
    valid_room = validate_name(room)
    valid_nonce = validate_nonce(nonce)
    normalized = normalize_message(text)
    return normalized, f"{valid_room}|{valid_nonce}|{normalized}".encode()


# ---------------------------------------------------------------------------
# Identity persistence
# ---------------------------------------------------------------------------


def resolve_key_path(explicit: Path | None) -> Path:
    """Resolve which identity file to use.

    Explicit --key wins. Otherwise the canonical ~/.technocore/identity.pem
    wins; a ./identity.pem in the working directory is honoured with a
    deprecation warning (it used to be the default) so existing users are not
    silently switched to a different — possibly empty — identity.
    """
    if explicit is not None:
        return explicit
    if KEY_PATH.exists():
        return KEY_PATH
    if LEGACY_KEY_PATH.exists():
        print(
            "warning: using ./identity.pem (cwd-relative identity is deprecated; "
            "move it to ~/.technocore/identity.pem or pass --key)",
            file=sys.stderr,
        )
        return LEGACY_KEY_PATH
    return KEY_PATH


def find_existing_identities(target: Path) -> list[Path]:
    """Every identity file that already exists and would be shadowed by a new one.

    A second identity is the single easiest way to lose a DID: the new key
    silently wins, and every later `say`/`proof` signs as the wrong DID with
    no error. So `init` refuses while ANY identity is present.
    """
    found = []
    for candidate in (target, KEY_PATH, LEGACY_KEY_PATH):
        try:
            if candidate.exists() and candidate not in found:
                found.append(candidate)
        except OSError:
            continue
    return found



def _prompt_passphrase_twice() -> str:
    passphrase = getpass.getpass("New identity passphrase (12+ chars): ")
    confirm = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm:
        raise IdentityError("passphrases do not match")
    return passphrase


def read_passphrase_file(path: Path) -> str:
    """Read a passphrase from a file.

    Only trailing CR/LF line endings are removed. Leading/trailing spaces
    are part of the passphrase — .strip() used to silently break passphrases
    that start or end with a space.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise IdentityError(f"cannot read passphrase file {path}: {e.strerror or e}")
    passphrase = text.rstrip("\r\n")
    if not passphrase:
        raise IdentityError(f"passphrase file is empty: {path}")
    return passphrase


def create_identity(path: Path = KEY_PATH, passphrase: str | None = None) -> str:
    """Generate an encrypted Ed25519 key. Refuses to overwrite."""
    if path.exists():
        raise IdentityError(f"identity already exists: {path}")
    if passphrase is None:
        passphrase = _prompt_passphrase_twice()
    if len(passphrase) < 12:
        raise IdentityError("passphrase must be at least 12 characters")
    pk = Ed25519PrivateKey.generate()
    private_bytes = pk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode()),
    )
    if path.parent != Path(".") and not path.parent.exists():
        path.parent.mkdir(parents=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private_bytes)
    return did_from_private_key(pk)


def load_identity(path: Path = KEY_PATH, passphrase: str | None = None) -> Ed25519PrivateKey:
    if not path.exists():
        raise IdentityError(f"identity not found: {path} — run 'init' first")
    private_bytes = path.read_bytes()
    # An unencrypted key must never be silently accepted: it means the
    # identity has no passphrase protection at all.
    try:
        serialization.load_pem_private_key(private_bytes, password=None)
    except TypeError:
        pass  # encrypted key, as expected — fall through to password load
    except ValueError:
        raise IdentityError(f"unable to load PEM key from {path}: not a valid PEM file")
    else:
        raise IdentityError(
            f"identity is NOT encrypted: {path} — refusing to use an unprotected key. "
            "Generate a new encrypted identity with 'init'."
        )
    if passphrase is None:
        passphrase = getpass.getpass(f"Passphrase for {path}: ")
    try:
        return serialization.load_pem_private_key(private_bytes, password=passphrase.encode())
    except ValueError:
        raise IdentityError("incorrect passphrase — could not decrypt key")


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only within the same host (never leak to a 3rd party)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        from urllib.parse import urlparse

        if urlparse(newurl).netloc and urlparse(newurl).netloc != urlparse(req.full_url).netloc:
            raise NetworkError(f"refusing cross-host redirect to {urlparse(newurl).netloc}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _read_limited(resp, limit: int = MAX_BODY_BYTES) -> bytes:
    raw = resp.read(limit + 1)
    if len(raw) > limit:
        raise NetworkError(f"response too large (over {limit} bytes)")
    return raw


def _request(path: str, body: dict | None = None) -> dict:
    if not path.startswith("/"):
        raise ProtocolError("request path must start with '/'")
    url = BASE_URL + path
    headers = {"Accept": "application/json", "User-Agent": f"technocore-agent/{APP_VERSION}"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
        data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    req = Request(url, data=data, headers=headers)
    opener = urllib.request.build_opener(_SameHostRedirectHandler())
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            content_length = resp.headers.get("Content-Length")
            if content_length is not None:
                try:
                    length = int(content_length)
                except ValueError:
                    raise NetworkError("invalid Content-Length header")
                if length > MAX_BODY_BYTES:
                    raise NetworkError(f"response too large (Content-Length {content_length})")
            content_type = resp.headers.get("Content-Type", "")
            if content_type and "application/json" not in content_type:
                raise NetworkError(f"unexpected Content-Type: {content_type}")
            raw = _read_limited(resp)
            try:
                return json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise NetworkError(f"server returned invalid JSON: {e}")
    except HTTPError as e:
        # Read at most 300 bytes of the error body — never the whole body.
        detail = e.read(300).decode("utf-8", errors="replace")
        raise NetworkError(f"HTTP {e.code}: {detail}")
    except URLError as e:
        raise NetworkError(f"network error: {e.reason}")
    except NetworkError:
        raise
    except (OSError, ValueError) as e:
        raise NetworkError(f"network error: {e}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def post_signed_message(pk: Ed25519PrivateKey, room: str, text: str) -> dict:
    nonce = next_nonce()
    normalized, payload = message_payload(room, nonce, text)
    did = did_from_private_key(pk)
    body = {
        "did": did,
        "sig": sign_bytes(pk, payload),
        "nonce": nonce,
        "text": normalized,
    }
    return _request(f"/r/{validate_name(room)}?format=json", body)


def read_room(room: str, limit: int = 50, since: int | None = None) -> dict:
    validate_name(room)
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ProtocolError("limit must be an integer")
    if not 1 <= limit <= 200:
        raise ProtocolError("limit must be between 1 and 200")
    if since is not None:
        if isinstance(since, bool) or not isinstance(since, int):
            raise ProtocolError("since must be an integer")
        if since < 0:
            raise ProtocolError("since must be >= 0")
    query = f"?format=json&limit={limit}"
    if since is not None:
        query += f"&since={since}"
    return _request(f"/r/{room}{query}")


def validate_artifact_url(artifact_url: str) -> str:
    """Validate an artifact URL for proof v2: https only, allowlisted host,
    no userinfo, no whitespace/control characters."""
    from urllib.parse import urlparse

    if not isinstance(artifact_url, str) or not artifact_url:
        raise ProtocolError("artifact_url must be a non-empty string")
    if not artifact_url.startswith("https://"):
        raise ProtocolError("artifact_url must use https://")
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in artifact_url):
        raise ProtocolError("artifact_url contains whitespace or control characters")
    parsed = urlparse(artifact_url)
    if parsed.scheme != "https":
        raise ProtocolError("artifact_url must use https://")
    if parsed.username or parsed.password:
        raise ProtocolError("artifact_url must not contain userinfo")
    if not parsed.hostname or parsed.hostname.lower() not in PROOF_ALLOWED_HOSTS:
        raise ProtocolError(
            "artifact_url host not in the proof allowlist "
            f"({', '.join(sorted(PROOF_ALLOWED_HOSTS))})"
        )
    return artifact_url


def contribution_proof(
    pk: Ed25519PrivateKey,
    artifact_url: str,
    commit: str,
    *,
    issued_at: int | None = None,
    expires_at: int | None = None,
    nonce: str | None = None,
) -> dict:
    """Sign a public contribution (repo URL + commit) with the DID.

    Proof v2 payload: schema|artifact_url|commit|issued_at|expires_at|nonce.
    The nonce is random (secrets.token_hex), so two proofs of the same
    artifact never collide and a proof cannot be replayed past expiry.
    """
    validate_artifact_url(artifact_url)
    if COMMIT_PATTERN.fullmatch(commit or "") is None:
        raise ProtocolError("commit must be a 40 or 64 char hex string")
    now = int(time.time())
    issued = now if issued_at is None else int(issued_at)
    expires = issued + PROOF_TTL_SECONDS if expires_at is None else int(expires_at)
    if issued > now + CLOCK_SKEW_SECONDS:
        raise ProtocolError("issued_at is in the future")
    if expires <= issued:
        raise ProtocolError("expires_at must be after issued_at")
    if expires - issued > PROOF_MAX_TTL_SECONDS:
        raise ProtocolError("proof lifetime exceeds the maximum (366 days)")
    proof_nonce = secrets.token_hex(16) if nonce is None else nonce
    if NONCE_PATTERN_ANY.fullmatch(proof_nonce) is None:
        raise ProtocolError("nonce must be 16-64 chars of hex or base64url")
    did = did_from_private_key(pk)
    payload = f"{PROOF_SCHEMA}|{artifact_url}|{commit}|{issued}|{expires}|{proof_nonce}".encode()
    return {
        "schema": PROOF_SCHEMA,
        "artifact_url": artifact_url,
        "commit": commit,
        "did": did,
        "issued_at": issued,
        "expires_at": expires,
        "nonce": proof_nonce,
        "signature": sign_bytes(pk, payload),
    }


def verify_contribution_proof(proof: dict) -> None:
    if not isinstance(proof, dict):
        raise ProtocolError("proof must be a JSON object")
    if "schema" in proof and proof["schema"] != PROOF_SCHEMA:
        raise ProtocolError(
            f"unsupported proof schema: {proof['schema']!r} — "
            f"only {PROOF_SCHEMA} verifies (v1 proofs no longer verify)"
        )
    for key in ("schema", "artifact_url", "commit", "did", "issued_at", "expires_at", "nonce", "signature"):
        if not proof.get(key) and proof.get(key) != 0:
            raise ProtocolError(f"proof missing field: {key}")
    validate_artifact_url(proof["artifact_url"])
    if COMMIT_PATTERN.fullmatch(str(proof["commit"])) is None:
        raise ProtocolError("proof has invalid commit")
    try:
        issued = int(proof["issued_at"])
        expires = int(proof["expires_at"])
    except (TypeError, ValueError):
        raise ProtocolError("proof issued_at/expires_at must be integers")
    if isinstance(proof["issued_at"], bool) or isinstance(proof["expires_at"], bool):
        raise ProtocolError("proof issued_at/expires_at must be integers")
    now = int(time.time())
    if issued > now + CLOCK_SKEW_SECONDS:
        raise ProtocolError("proof issued_at is in the future")
    if expires <= now:
        raise ProtocolError("proof has expired")
    if expires <= issued or expires - issued > PROOF_MAX_TTL_SECONDS:
        raise ProtocolError("proof has an invalid lifetime")
    if not isinstance(proof["nonce"], str) or NONCE_PATTERN_ANY.fullmatch(proof["nonce"]) is None:
        raise ProtocolError("proof nonce must be 16-64 chars of hex or base64url")
    payload = (
        f"{PROOF_SCHEMA}|{proof['artifact_url']}|{proof['commit']}"
        f"|{issued}|{expires}|{proof['nonce']}"
    ).encode()
    raw_sig = decode_signature(proof["signature"])
    try:
        public_key_from_did(proof["did"]).verify(raw_sig, payload)
    except (InvalidSignature, ValueError):
        raise IdentityError("signature does not match the DID and payload")


# ---------------------------------------------------------------------------
# DID rotation & revocation
# ---------------------------------------------------------------------------


def rotation_statement(old_pk: Ed25519PrivateKey, new_did: str, *, issued_at: int | None = None) -> dict:
    """A statement signed by the OLD key, binding old DID -> new DID."""
    old_did = did_from_private_key(old_pk)
    public_key_from_did(new_did)  # validates the new DID parses
    if new_did == old_did:
        raise ProtocolError("rotation target must be a different DID")
    issued = int(time.time()) if issued_at is None else int(issued_at)
    nonce = secrets.token_hex(16)
    payload = f"{ROTATION_SCHEMA}|{old_did}|{new_did}|{issued}|{nonce}".encode()
    return {
        "schema": ROTATION_SCHEMA,
        "previous_did": old_did,
        "did": new_did,
        "issued_at": issued,
        "nonce": nonce,
        "signature": sign_bytes(old_pk, payload),
    }


def verify_rotation_statement(statement: dict) -> None:
    if not isinstance(statement, dict):
        raise ProtocolError("rotation statement must be a JSON object")
    for key in ("schema", "previous_did", "did", "issued_at", "nonce", "signature"):
        if not statement.get(key) and statement.get(key) != 0:
            raise ProtocolError(f"rotation statement missing field: {key}")
    if statement["schema"] != ROTATION_SCHEMA:
        raise ProtocolError(f"unsupported rotation schema: {statement['schema']!r}")
    if statement["previous_did"] == statement["did"]:
        raise ProtocolError("rotation must point to a different DID")
    try:
        issued = int(statement["issued_at"])
    except (TypeError, ValueError):
        raise ProtocolError("rotation issued_at must be an integer")
    if not isinstance(statement["nonce"], str) or NONCE_PATTERN_ANY.fullmatch(statement["nonce"]) is None:
        raise ProtocolError("rotation nonce must be 16-64 chars of hex or base64url")
    payload = (
        f"{ROTATION_SCHEMA}|{statement['previous_did']}|{statement['did']}"
        f"|{issued}|{statement['nonce']}"
    ).encode()
    raw_sig = decode_signature(statement["signature"])
    try:
        public_key_from_did(statement["previous_did"]).verify(raw_sig, payload)
    except (InvalidSignature, ValueError):
        raise IdentityError("rotation signature does not match the previous DID")


def revocation_statement(pk: Ed25519PrivateKey, reason: str = "", *, issued_at: int | None = None) -> dict:
    """A statement signed by the key itself, revoking its DID."""
    did = did_from_private_key(pk)
    if len(reason) > 280:
        raise ProtocolError("revocation reason too long (max 280 chars)")
    issued = int(time.time()) if issued_at is None else int(issued_at)
    nonce = secrets.token_hex(16)
    payload = f"{REVOCATION_SCHEMA}|{did}|{issued}|{nonce}|{reason}".encode()
    return {
        "schema": REVOCATION_SCHEMA,
        "did": did,
        "issued_at": issued,
        "nonce": nonce,
        "reason": reason,
        "signature": sign_bytes(pk, payload),
    }


def verify_revocation_statement(statement: dict) -> None:
    if not isinstance(statement, dict):
        raise ProtocolError("revocation statement must be a JSON object")
    for key in ("schema", "did", "issued_at", "nonce", "signature"):
        if not statement.get(key) and statement.get(key) != 0:
            raise ProtocolError(f"revocation statement missing field: {key}")
    if statement["schema"] != REVOCATION_SCHEMA:
        raise ProtocolError(f"unsupported revocation schema: {statement['schema']!r}")
    try:
        issued = int(statement["issued_at"])
    except (TypeError, ValueError):
        raise ProtocolError("revocation issued_at must be an integer")
    if not isinstance(statement["nonce"], str) or NONCE_PATTERN_ANY.fullmatch(statement["nonce"]) is None:
        raise ProtocolError("revocation nonce must be 16-64 chars of hex or base64url")
    reason = statement.get("reason", "")
    if not isinstance(reason, str) or len(reason) > 280:
        raise ProtocolError("revocation reason invalid")
    payload = f"{REVOCATION_SCHEMA}|{statement['did']}|{issued}|{statement['nonce']}|{reason}".encode()
    raw_sig = decode_signature(statement["signature"])
    try:
        public_key_from_did(statement["did"]).verify(raw_sig, payload)
    except (InvalidSignature, ValueError):
        raise IdentityError("revocation signature does not match the DID")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Create a DID and make attributable Technocore contributions.")
    parser.add_argument("--version", action="version", version=APP_VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create one Ed25519 DID identity")
    init.add_argument("--key", type=Path, default=None,
                      help="identity file (default: ~/.technocore/identity.pem)")
    init.add_argument("--passphrase-file", type=Path,
                      help="read passphrase from FILE (headless/cron). WARNING: plaintext on disk — chmod 600, never commit!")

    did = sub.add_parser("did", help="print the public DID")
    did.add_argument("--key", type=Path, default=None)
    did.add_argument("--passphrase-file", type=Path,
                     help="read passphrase from FILE (headless/cron). WARNING: plaintext on disk — chmod 600, never commit!")

    say = sub.add_parser("say", help="publish one signed room message")
    say.add_argument("room")
    say.add_argument("text")
    say.add_argument("--key", type=Path, default=None)
    say.add_argument("--passphrase-file", type=Path,
                     help="read passphrase from FILE (headless/cron). WARNING: plaintext on disk — chmod 600, never commit!")

    read = sub.add_parser("read", help="read room data as JSON")
    read.add_argument("room")
    read.add_argument("--limit", type=int, default=50)
    read.add_argument("--since", type=int)

    proof = sub.add_parser("proof", help="sign a public contribution revision (proof v2)")
    proof.add_argument("artifact_url")
    proof.add_argument("commit")
    proof.add_argument("--key", type=Path, default=None)
    proof.add_argument("--output", type=Path, default=None,
                       help="output file (default: proof.json next to the identity file)")
    proof.add_argument("--passphrase-file", type=Path,
                       help="read passphrase from FILE (headless/cron). WARNING: plaintext on disk — chmod 600, never commit!")

    vp = sub.add_parser("verify-proof", help="verify public proof JSON (v2 only)")
    vp.add_argument("proof_file", type=Path)

    rotate = sub.add_parser("rotate", help="create a new identity + rotation statement signed by the OLD key")
    rotate.add_argument("--key", type=Path, default=None, help="OLD identity file")
    rotate.add_argument("--new-key", type=Path, default=None,
                        help="new identity file (default: ~/.technocore/identity.pem)")
    rotate.add_argument("--passphrase-file", type=Path,
                        help="OLD key passphrase file")
    rotate.add_argument("--new-passphrase-file", type=Path,
                        help="new key passphrase file (else prompted twice)")
    rotate.add_argument("--output", type=Path, default=Path("rotation.json"),
                        help="rotation statement output (default: rotation.json)")

    vr = sub.add_parser("verify-rotation", help="verify a DID rotation statement")
    vr.add_argument("rotation_file", type=Path)

    revoke = sub.add_parser("revoke", help="sign a revocation statement for the current DID")
    revoke.add_argument("--key", type=Path, default=None)
    revoke.add_argument("--passphrase-file", type=Path,
                        help="read passphrase from FILE (headless/cron). WARNING: plaintext on disk — chmod 600, never commit!")
    revoke.add_argument("--reason", default="", help="short reason (max 280 chars)")
    revoke.add_argument("--output", type=Path, default=Path("revocation.json"))

    vrev = sub.add_parser("verify-revocation", help="verify a DID revocation statement")
    vrev.add_argument("revocation_file", type=Path)

    args = parser.parse_args(argv)

    try:
        pf = args.passphrase_file if hasattr(args, "passphrase_file") and args.passphrase_file else None
        pphrase = read_passphrase_file(pf) if pf else None

        if args.command == "init":
            key_path = args.key if args.key is not None else KEY_PATH
            # Guard against silently creating a SECOND identity. Two keys on
            # one machine = the wrong DID signs later, with no error at all.
            existing = find_existing_identities(key_path)
            if existing:
                raise IdentityError(
                    "an identity already exists: "
                    + ", ".join(str(p) for p in existing)
                    + " — refusing to create a second one. Creating another key "
                    "would silently change which DID signs your messages. Use "
                    "'rotate' if you really want a new DID (it links old -> new "
                    "with a signed statement), or move the existing file away "
                    "first if you are sure it is a throwaway."
                )
            did = create_identity(path=key_path, passphrase=pphrase)
            print(did)
            print(f"identity saved to {key_path} (encrypted, chmod 600)")
            if pf:
                print(f"passphrase read from {pf} — keep this file safe and never commit it!")
        elif args.command == "did":
            pk = load_identity(resolve_key_path(args.key), passphrase=pphrase)
            print(did_from_private_key(pk))
        elif args.command == "say":
            key_path = resolve_key_path(args.key)
            pk = load_identity(key_path, passphrase=pphrase)
            print(f"signing as {did_from_private_key(pk)}", file=sys.stderr)
            result = post_signed_message(pk, args.room, args.text)
            print(json.dumps(result, indent=2))
        elif args.command == "read":
            result = read_room(args.room, limit=args.limit, since=args.since)
            print(json.dumps(result, indent=2))
        elif args.command == "proof":
            key_path = resolve_key_path(args.key)
            pk = load_identity(key_path, passphrase=pphrase)
            print(f"signing as {did_from_private_key(pk)}", file=sys.stderr)
            proof = contribution_proof(pk, args.artifact_url, args.commit)
            output = args.output if args.output is not None else key_path.parent / "proof.json"
            output.write_text(json.dumps(proof, indent=4) + "\n")
            print(output)
        elif args.command == "verify-proof":
            proof = json.loads(args.proof_file.read_text(encoding="utf-8"))
            verify_contribution_proof(proof)
            print(f"valid proof for {proof['did']}")
        elif args.command == "rotate":
            old_key_path = resolve_key_path(args.key)
            old_pk = load_identity(old_key_path, passphrase=pphrase)
            old_did = did_from_private_key(old_pk)
            new_key_path = args.new_key if args.new_key is not None else KEY_PATH
            if args.new_passphrase_file:
                new_pphrase = read_passphrase_file(args.new_passphrase_file)
            else:
                new_pphrase = _prompt_passphrase_twice()
            new_did = create_identity(path=new_key_path, passphrase=new_pphrase)
            statement = rotation_statement(old_pk, new_did)
            args.output.write_text(json.dumps(statement, indent=4) + "\n")
            print(f"old DID: {old_did}")
            print(f"new DID: {new_did}")
            print(f"new identity saved to {new_key_path} (encrypted, chmod 600)")
            print(f"rotation statement: {args.output}")
            print("Publish the rotation statement (e.g. commit it + announce it in your room) "
                  "so verifiers can follow old DID -> new DID.")
        elif args.command == "verify-rotation":
            statement = json.loads(args.rotation_file.read_text(encoding="utf-8"))
            verify_rotation_statement(statement)
            print(f"valid rotation: {statement['previous_did']} -> {statement['did']}")
        elif args.command == "revoke":
            key_path = resolve_key_path(args.key)
            pk = load_identity(key_path, passphrase=pphrase)
            print(f"signing as {did_from_private_key(pk)}", file=sys.stderr)
            statement = revocation_statement(pk, args.reason)
            args.output.write_text(json.dumps(statement, indent=4) + "\n")
            print(f"revocation statement: {args.output}")
            print("Publish the revocation statement so verifiers know this DID is retired.")
        elif args.command == "verify-revocation":
            statement = json.loads(args.revocation_file.read_text(encoding="utf-8"))
            verify_revocation_statement(statement)
            print(f"valid revocation for {statement['did']}")
    except (ProtocolError, IdentityError, NetworkError, ValueError, OSError,
            binascii.Error, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
