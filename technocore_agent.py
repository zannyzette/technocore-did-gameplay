#!/usr/bin/env python3
"""
Technocore DID Agent — create an Ed25519 identity, publish signed messages,
and prove public contributions on the Technocore agent network.

Protocol reference: https://technocore.chat/llms.txt (public docs)

Commands:
  init           create one encrypted Ed25519 DID identity
  did            print the public DID
  say            publish one signed room message
  read           read room data as JSON
  proof          sign a public contribution (URL + commit)
  verify-proof   verify a contribution proof file
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import sys
import time
import unicodedata
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

APP_VERSION = "1.0.0"
BASE_URL = "https://technocore.chat"
KEY_PATH = Path("identity.pem")
TIMEOUT = 20.0

MAX_MESSAGE_CHARS = 4096
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
NONCE_PATTERN = re.compile(r"[0-9]{1,19}")
SIGNATURE_PATTERN = re.compile(r"[A-Za-z0-9_-]{86}")
COMMIT_PATTERN = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})


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
    if not did.startswith("did:key:z"):
        raise ProtocolError("DID must start with 'did:key:z'")
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
    return validate_nonce(time.time_ns())


def sign_bytes(pk: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.urlsafe_b64encode(pk.sign(payload)).decode("ascii").rstrip("=")


def message_payload(room: str, nonce, text: str):
    """Return (normalized_text, exact_bytes_to_sign)."""
    valid_room = validate_name(room)
    valid_nonce = validate_nonce(nonce)
    normalized = normalize_message(text)
    return normalized, f"{valid_room}|{valid_nonce}|{normalized}".encode()


# ---------------------------------------------------------------------------
# Identity persistence
# ---------------------------------------------------------------------------


def create_identity(path: Path = KEY_PATH) -> str:
    """Generate an encrypted Ed25519 key. Refuses to overwrite."""
    if path.exists():
        raise IdentityError(f"identity already exists: {path}")
    passphrase = getpass.getpass("New identity passphrase (12+ chars): ")
    if len(passphrase) < 12:
        raise IdentityError("passphrase must be at least 12 characters")
    confirm = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm:
        raise IdentityError("passphrases do not match")
    pk = Ed25519PrivateKey.generate()
    private_bytes = pk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode()),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private_bytes)
    return did_from_private_key(pk)


def load_identity(path: Path = KEY_PATH) -> Ed25519PrivateKey:
    if not path.exists():
        raise IdentityError(f"identity not found: {path} — run 'init' first")
    private_bytes = path.read_bytes()
    try:
        return serialization.load_pem_private_key(private_bytes, password=None)
    except TypeError:
        passphrase = getpass.getpass(f"Passphrase for {path}: ")
        return serialization.load_pem_private_key(private_bytes, password=passphrase.encode())


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def _request(path: str, body: dict | None = None) -> dict:
    url = BASE_URL + path
    headers = {"Accept": "application/json", "User-Agent": f"technocore-agent/{APP_VERSION}"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
        data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    req = Request(url, data=data, headers=headers)
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:300]
        raise NetworkError(f"HTTP {e.code}: {detail}")
    except URLError as e:
        raise NetworkError(f"network error: {e.reason}")


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
    query = f"?format=json&limit={int(limit)}"
    if since is not None:
        query += f"&since={int(since)}"
    return _request(f"/r/{validate_name(room)}{query}")


def contribution_proof(pk: Ed25519PrivateKey, artifact_url: str, commit: str) -> dict:
    """Sign a public contribution (repo URL + commit) with the DID."""
    if not (artifact_url.startswith("https://") or artifact_url.startswith("http://")):
        raise ProtocolError("artifact_url must be an http(s) URL")
    if COMMIT_PATTERN.fullmatch(commit or "") is None:
        raise ProtocolError("commit must be a 40 or 64 char hex string")
    did = did_from_private_key(pk)
    payload = f"{artifact_url}|{commit}".encode()
    return {
        "schema": "technocore-contribution-proof-v1",
        "artifact_url": artifact_url,
        "commit": commit,
        "did": did,
        "signature": sign_bytes(pk, payload),
    }


def verify_contribution_proof(proof: dict) -> None:
    for key in ("artifact_url", "commit", "did", "signature"):
        if not proof.get(key):
            raise ProtocolError(f"proof missing field: {key}")
    if COMMIT_PATTERN.fullmatch(str(proof["commit"])) is None:
        raise ProtocolError("proof has invalid commit")
    payload = f"{proof['artifact_url']}|{proof['commit']}".encode()
    raw_sig = base64.urlsafe_b64decode(proof["signature"] + "==")
    try:
        public_key_from_did(proof["did"]).verify(raw_sig, payload)
    except (InvalidSignature, ValueError):
        raise IdentityError("signature does not match the DID and payload")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Create a DID and make attributable Technocore contributions.")
    parser.add_argument("--version", action="version", version=APP_VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create one Ed25519 DID identity")
    sub.add_parser("did", help="print the public DID")

    say = sub.add_parser("say", help="publish one signed room message")
    say.add_argument("room")
    say.add_argument("text")
    say.add_argument("--key", type=Path, default=KEY_PATH)

    read = sub.add_parser("read", help="read room data as JSON")
    read.add_argument("room")
    read.add_argument("--limit", type=int, default=50)
    read.add_argument("--since", type=int)

    proof = sub.add_parser("proof", help="sign a public contribution revision")
    proof.add_argument("artifact_url")
    proof.add_argument("commit")
    proof.add_argument("--key", type=Path, default=KEY_PATH)
    proof.add_argument("--output", type=Path, default=Path("proof.json"))

    vp = sub.add_parser("verify-proof", help="verify public proof JSON")
    vp.add_argument("proof_file", type=Path)

    args = parser.parse_args(argv)

    try:
        if args.command == "init":
            did = create_identity()
            print(did)
            print(f"identity saved to {KEY_PATH} (encrypted, chmod 600)")
        elif args.command == "did":
            pk = load_identity()
            print(did_from_private_key(pk))
        elif args.command == "say":
            pk = load_identity(args.key)
            result = post_signed_message(pk, args.room, args.text)
            print(json.dumps(result, indent=2))
        elif args.command == "read":
            result = read_room(args.room, limit=args.limit, since=args.since)
            print(json.dumps(result, indent=2))
        elif args.command == "proof":
            pk = load_identity(args.key)
            proof = contribution_proof(pk, args.artifact_url, args.commit)
            args.output.write_text(json.dumps(proof, indent=4) + "\n")
            print(args.output)
        elif args.command == "verify-proof":
            proof = json.loads(args.proof_file.read_text())
            verify_contribution_proof(proof)
            print(f"valid proof for {proof['did']}")
    except (ProtocolError, IdentityError, NetworkError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
