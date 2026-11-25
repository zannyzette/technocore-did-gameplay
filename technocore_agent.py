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
  faucet           free devnet FLOP for the SS58 address of your own did:key

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
import hashlib
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

APP_VERSION = "1.3.0"
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


# --- FLOP devnet faucet -----------------------------------------------------
# Free devnet FLOP. Devnet FLOP is a TEST token with no value — it is not
# testnet or mainnet FLOP, and it is not an airdrop.
#   Guide:  https://faucet.flop.network/llms.txt
#   Limits: https://faucet.flop.network/limits
#   Chain:  https://faucet.flop.network/chain
#
# The point of this section: your did:key IS an Ed25519 key, so it already has
# an SS58 address on the FLOP devnet. You do not need a second wallet — derive
# the address from the identity you already have and ask the faucet to fund it.
# Two SEPARATE hosts. faucet.flop.network serves Testnet only; the devnet faucet
# lives on its own subdomain. Verified 2026-11-25: /limits?network=devnet on the
# testnet host silently returns testnet data, so the host — not a query param —
# decides which chain you are asking. /chain is cross-checked before signing.
FAUCET_HOSTS = {
    "testnet": "https://faucet.flop.network",
    "devnet": "https://faucet.devnet.flop.network",
}
FAUCET_API = FAUCET_HOSTS["testnet"]
FAUCET_CHAT_ROOM = "flop-devnet-faucet"        # devnet bot lane
FAUCET_TESTNET_CHAT_ROOM = "flop-testnet-faucet"
FAUCET_SS58_FORMAT = 42          # from GET /chain -> ss58Format
FAUCET_CLIENT_LABEL = "technocore-did-gameplay"
FAUCET_TIMEOUT = 90.0   # a signed claim waits for finalization; 20s is too short

# Two networks, two different lanes — do not mix them up:
#   testnet : 10 FLOP per wallet per 24h, SIGNED claim at
#             POST /v1/testnet/agent-claims. This is the network the FLOP
#             testnet campaign actually runs on.
#   devnet  : 25 FLOP per address per 24h, plain POST /fund. Throwaway tokens.
# An address funded on the agent lane keeps agent rules everywhere afterwards,
# so on devnet always use POST /fund (25) before any agent-lane request (2).
FAUCET_NETWORKS = ("testnet", "devnet")
FAUCET_DEFAULT_NETWORK = "testnet"
FAUCET_AGENT_CLAIM_PATH = "/v1/testnet/agent-claims"
# Exactly what the faucet wants signed (see flop.network/llms.txt).
FAUCET_AGENT_SIGN_TEMPLATE = "flop-faucet-agent/v1|{genesis}|{address}|{nonce}"
FAUCET_RPC_HTTP = {
    "testnet": "https://testnet.flop.network",
    "devnet": "https://rpc.devnet.flop.network",
}
SS58_PREIMAGE = b"SS58PRE"

# Two lanes, and the ORDER MATTERS. An address funded on the agent lane keeps
# the agent rules (2 FLOP, needs on-chain spend before a repeat) on EVERY lane
# afterwards. So always use the anonymous POST /fund lane (25 FLOP) first.
FAUCET_ANON_FLOP = 25
FAUCET_AGENT_FLOP = 2


def ss58_address_from_pubkey(pubkey: bytes, fmt: int = FAUCET_SS58_FORMAT) -> str:
    """SS58 (Substrate address format) for a raw 32-byte public key."""
    if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
        raise ProtocolError("public key must be 32 raw bytes")
    payload = bytes([fmt]) + bytes(pubkey)
    checksum = hashlib.blake2b(SS58_PREIMAGE + payload, digest_size=64).digest()[:2]
    return _b58_encode(payload + checksum)


def validate_ss58(address: str, fmt: int = FAUCET_SS58_FORMAT) -> dict:
    """Check an SS58 string really is a usable address: length + checksum.

    A typo'd or hallucinated address fails at claim time with a confusing
    `claim_signature_invalid`. Catching it here costs nothing and is the single
    most common self-inflicted failure, so it gets its own function.
    """
    if not isinstance(address, str) or not address:
        raise ProtocolError("address must be a non-empty string")
    try:
        raw = _b58_decode(address)
    except (ValueError, IndexError):
        raise ProtocolError("address has invalid base58btc characters")
    if len(raw) != 35:
        raise ProtocolError(
            f"address decodes to {len(raw)} bytes, expected 35 "
            f"(prefix 1 + account 32 + checksum 2)"
        )
    payload, checksum = raw[:-2], raw[-2:]
    expected = hashlib.blake2b(SS58_PREIMAGE + payload, digest_size=64).digest()[:2]
    if checksum != expected:
        raise ProtocolError("address checksum does not match — it is not a real address")
    return {"address": address, "format": payload[0],
            "account": payload[1:].hex(), "valid": True}


def ss58_address_from_did(did: str) -> str:
    """SS58 address of the SAME Ed25519 key that a did:key names.

    This is the whole trick of the FLOP faucet: no separate wallet, no seed to
    copy around. The DID already commits to the key the devnet wants.
    """
    pk = public_key_from_did(did)
    raw = pk.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return ss58_address_from_pubkey(raw)


def _faucet_request(path: str, body: dict | None = None,
                    network: str = FAUCET_DEFAULT_NETWORK) -> dict:
    """GET/POST against ONE network's faucet host."""
    if not path.startswith("/"):
        raise ProtocolError("request path must start with '/'")
    if network not in FAUCET_HOSTS:
        raise ProtocolError(f"network must be one of {FAUCET_NETWORKS}")
    headers = {
        "Accept": "application/json",
        "User-Agent": f"technocore-agent/{APP_VERSION}",
    }
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
        data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    req = Request(FAUCET_HOSTS[network] + path, data=data, headers=headers)
    # Reads are retried (the faucet sits behind Cloudflare and occasionally
    # stalls); writes are NOT — a retried POST can pay twice.
    attempts = 3 if data is None else 1
    try:
        for attempt in range(attempts):
            try:
                with urlopen(req, timeout=TIMEOUT) as resp:
                    raw = _read_limited(resp)
                    try:
                        return json.loads(raw.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        raise NetworkError(f"faucet returned invalid JSON: {e}")
            except (URLError, OSError) as e:
                if attempt == attempts - 1:
                    raise
                time.sleep(1.5 * (attempt + 1))
    except HTTPError as e:
        # Refusals are JSON with error/reason/action — keep them readable.
        detail = e.read(2000).decode("utf-8", errors="replace")
        try:
            parsed = json.loads(detail)
        except (json.JSONDecodeError, ValueError):
            parsed = None
        if isinstance(parsed, dict):
            parsed.setdefault("_httpStatus", e.code)
            return parsed
        raise NetworkError(f"faucet HTTP {e.code}: {detail[:200]}")
    except URLError as e:
        raise NetworkError(f"network error: {e.reason}")
    except NetworkError:
        raise
    except (OSError, ValueError) as e:
        raise NetworkError(f"network error: {e}")


def faucet_status(network: str = FAUCET_DEFAULT_NETWORK) -> dict:
    """Live limits + chain identity for ONE network (testnet or devnet)."""
    if network not in FAUCET_NETWORKS:
        raise ProtocolError(f"network must be one of {FAUCET_NETWORKS}")
    limits = _faucet_request("/limits", network=network)
    chain = _faucet_request("/chain", network=network)
    served = chain.get("network")
    if served != network:
        # The faucet tells you which chain it serves; never sign for a guess.
        raise NetworkError(
            f"faucet reports network '{served}' but '{network}' was requested"
        )
    faucet = limits.get("faucet") or {}
    anon = faucet.get("anonymous") or {}
    agent = faucet.get("agent") or {}
    daily = faucet.get("dailyCap") or {}
    return {
        "network": limits.get("network"),
        "faucetStatus": faucet.get("status"),
        "anonymousGrantFlop": anon.get("grantFlop"),
        "anonymousCooldownSeconds": anon.get("addressCooldownSeconds"),
        "agentGrantFlop": agent.get("grantFlop"),
        "agentCooldownSeconds": agent.get("cooldownSeconds"),
        "agentRolloverRequiresSpend": agent.get("rolloverRequiresSpend"),
        "dailyRemainingFlop": daily.get("remainingFlop"),
        "chain": chain.get("chain"),
        "genesisHash": chain.get("genesisHash"),
        "ss58Format": chain.get("ss58Format"),
        "tokenSymbol": chain.get("tokenSymbol"),
        "rpc": chain.get("rpc"),
        "technocoreBot": (chain.get("technocoreBot") or {}).get("did"),
        "claimPath": (faucet.get("agent") or {}).get("claimPath"),
        "agentRolling24hCapFlop": (faucet.get("agent") or {}).get(
            "rolling24HourCapFlop"),
    }


def faucet_agent_claim_message(genesis_hash: str, address: str, nonce: str) -> str:
    """The exact UTF-8 text the Testnet faucet wants signed. No trimming."""
    return FAUCET_AGENT_SIGN_TEMPLATE.format(
        genesis=genesis_hash, address=address, nonce=str(nonce)
    )


def faucet_agent_claim(
    pk: Ed25519PrivateKey,
    address: str,
    nonce: str | int | None = None,
    network: str = "testnet",
) -> tuple[int, dict]:
    """Signed agent claim (10 FLOP / 24h on Testnet).

    Repeating a request with the SAME nonce is safe and is the documented way to
    check an earlier request: it returns the same transaction and never pays
    twice. A refusal is returned, never retried in a loop.
    """
    if network != "testnet":
        raise ProtocolError("the signed agent-claim lane exists on testnet only")
    # Validate the address FIRST: a malformed address must fail locally, before
    # any network call, so it can never be mistaken for a faucet-side refusal.
    validate_ss58(address)
    info = faucet_status(network)
    genesis = info.get("genesisHash")
    if not genesis:
        raise NetworkError("faucet /chain did not report a genesis hash")
    n = str(nonce if nonce is not None else int(time.time() * 1000))
    if NONCE_PATTERN.fullmatch(n) is None:
        raise ProtocolError("nonce must be 1-19 ASCII digits")
    message = faucet_agent_claim_message(genesis, address, n)
    signature = "0x" + pk.sign(message.encode("utf-8")).hex()
    status, reply = _faucet_request_full(
        FAUCET_AGENT_CLAIM_PATH,
        {"address": address, "nonce": n, "signature": signature},
        network=network,
    )
    return status, {"request": {"address": address, "nonce": n,
                                "message": message},
                    "reply": reply}


def _faucet_request_full(path: str, body: dict,
                         network: str = FAUCET_DEFAULT_NETWORK) -> tuple[int, dict]:
    """POST that also returns the HTTP status (needed for 401 vs 429 vs 5xx)."""
    if not path.startswith("/"):
        raise ProtocolError("request path must start with '/'")
    if network not in FAUCET_HOSTS:
        raise ProtocolError(f"network must be one of {FAUCET_NETWORKS}")
    req = Request(
        FAUCET_HOSTS[network] + path,
        data=json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode(),
        headers={"Accept": "application/json",
                 "Content-Type": "application/json; charset=utf-8",
                 "User-Agent": f"technocore-agent/{APP_VERSION}"},
    )
    try:
        with urlopen(req, timeout=FAUCET_TIMEOUT) as resp:
            raw = _read_limited(resp)
            return resp.status, json.loads(raw.decode("utf-8") or "{}")
    except HTTPError as e:
        detail = e.read(4000).decode("utf-8", errors="replace")
        try:
            parsed = json.loads(detail)
        except (json.JSONDecodeError, ValueError):
            parsed = {"raw": detail[:300]}
        if not isinstance(parsed, dict):
            parsed = {"raw": str(parsed)[:300]}
        parsed.setdefault("_httpStatus", e.code)
        return e.code, parsed
    except URLError as e:
        raise NetworkError(f"network error: {e.reason}")
    except (OSError, ValueError) as e:
        raise NetworkError(f"network error: {e}")


def faucet_claim(address: str, client: str = FAUCET_CLIENT_LABEL,
                 network: str = "devnet") -> dict:
    """POST /fund for one address. NEVER retries — a refusal is final for now.

    Refusals carry a stable `reason` and usually `retryAfterSeconds`. Looping on
    them is what gets a client throttled, so this returns the refusal to the
    caller instead of trying again.
    """
    if not isinstance(address, str) or not address.strip():
        raise ProtocolError("address must be a non-empty SS58 string")
    if network != "devnet":
        raise ProtocolError(
            "POST /fund is the devnet lane; testnet wants a signed claim "
            "(faucet_agent_claim)"
        )
    return _faucet_request("/fund", {"address": address.strip(), "client": client},
                           network=network)


def describe_faucet_outcome(result: dict, address: str = "?") -> tuple[bool, str]:
    """Turn a /fund reply into (funded?, human line). No guessing, no retry.

    The success body carries amount/tier/txHash but not the address, so pass in
    the address you asked for — otherwise the report reads "funded to ?".
    """
    if result.get("success"):
        return True, (
            f"funded {result.get('amount')} FLOP to {result.get('address') or address}"
            f" (tier {result.get('tier', '?')}, tx {result.get('txHash', '?')})"
        )
    reason = result.get("reason") or result.get("error") or "unknown"
    wait = result.get("retryAfterSeconds")
    action = result.get("action")
    line = f"NOT funded — reason={reason}"
    if wait:
        line += f", retry after {wait}s"
    if action:
        line += f", action={action}"
    return False, line


# System.Account storage map: twox128("System") ++ twox128("Account")
# ++ blake2_128(account_id) ++ account_id. Constant, published in Substrate docs.
ACCOUNT_STORAGE_PREFIX = ("0x26aa394eea5630e07c48ae0c9558cef7"
                          "b99d880ec681799c0cf30e8886371da9")
FLOP_DECIMALS = 18


def account_storage_key(ss58: str) -> str:
    """Storage key of System.Account for an SS58 address (format 42)."""
    info = validate_ss58(ss58)
    raw = _b58_decode(ss58)
    account = raw[1:33]
    digest = hashlib.blake2b(account, digest_size=16).digest()
    return ACCOUNT_STORAGE_PREFIX + digest.hex() + account.hex()


def _rpc_call(rpc_url: str, method: str, params: list, tries: int = 3) -> dict:
    """Minimal Substrate JSON-RPC over HTTP. Retries only on transport errors."""
    last = None
    for attempt in range(tries):
        try:
            req = Request(
                rpc_url,
                data=json.dumps({"id": 1, "jsonrpc": "2.0",
                                 "method": method, "params": params}).encode(),
                headers={"content-type": "application/json",
                         "user-agent": f"technocore-agent/{APP_VERSION}"},
            )
            with urlopen(req, timeout=TIMEOUT) as resp:
                reply = json.loads(_read_limited(resp).decode("utf-8"))
        except (URLError, OSError, ValueError, json.JSONDecodeError) as e:
            last = e
            time.sleep(1 + attempt)
            continue
        if "error" in reply:
            last = reply["error"]
            time.sleep(1 + attempt)
            continue
        return reply
    raise NetworkError(f"RPC {method} failed after {tries} tries: {last}")


def devnet_balance(ss58: str, network: str = FAUCET_DEFAULT_NETWORK,
                   rpc_url: str | None = None) -> dict:
    """FREE / RESERVED / FROZEN balance of an SS58 address on the FLOP devnet.

    Returns {"exists": False} when the account is not on chain yet — which is
    exactly what a just-requested grant looks like while it is still queued.
    """
    if rpc_url is None:
        if network not in FAUCET_RPC_HTTP:
            raise ProtocolError(f"network must be one of {FAUCET_NETWORKS}")
        rpc_url = FAUCET_RPC_HTTP[network]
    key = account_storage_key(ss58)
    header = _rpc_call(rpc_url, "chain_getHeader", []).get("result")
    value = _rpc_call(rpc_url, "state_getStorage", [key]).get("result")
    out = {
        "address": ss58,
        "block": int(header["number"], 16) if header else None,
        "exists": bool(value),
    }
    if not value:
        return out
    raw = bytes.fromhex(value[2:] if value.startswith("0x") else value)
    if len(raw) < 64:
        raise NetworkError(f"unexpected AccountInfo size: {len(raw)} bytes")
    scale = 10 ** FLOP_DECIMALS
    out.update({
        "nonce": int.from_bytes(raw[0:4], "little"),
        "providers": int.from_bytes(raw[8:12], "little"),
        "free": int.from_bytes(raw[16:32], "little") / scale,
        "reserved": int.from_bytes(raw[32:48], "little") / scale,
        "frozen": int.from_bytes(raw[48:64], "little") / scale,
    })
    return out


def faucet_chat_request(did: str, ss58: str, nonce: int | None = None) -> dict:
    """Post `!faucet request <ss58> <nonce>` to the Technocore faucet room.

    When <ss58> is the address of the SAME did:key, the bot submits the grant
    for you (2 FLOP, agent rules). For any other address it answers with an
    unsigned challenge you must sign with THAT account's key — this helper does
    not do that, because it would mean holding someone else's key.
    """
    n = int(nonce if nonce is not None else time.time() * 1000)
    text = f"!faucet request {ss58} {n}"
    return {"room": FAUCET_CHAT_ROOM, "nonce": n, "text": text, "did": did}


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

    faucet = sub.add_parser(
        "faucet",
        help="free devnet FLOP for your DID's own SS58 address",
        description=(
            "Derive the SS58 address of your did:key's Ed25519 key and ask the "
            "FLOP devnet faucet to fund it. Devnet FLOP is a test token with no "
            "value — not testnet or mainnet FLOP, not an airdrop."
        ),
    )
    faucet.add_argument("--network", choices=FAUCET_NETWORKS,
                        default=FAUCET_DEFAULT_NETWORK,
                        help="testnet = 10 FLOP signed claim (default); "
                             "devnet = 25 FLOP plain POST")
    faucet.add_argument("--nonce", default=None,
                        help="claim nonce (1-19 digits). Repeat the SAME nonce to "
                             "re-check a request without paying twice")
    faucet.add_argument("--check", action="store_true",
                        help="readiness check only: identity, address checksum, network, "
                             "limits. Sends nothing — safe to run any time")
    faucet.add_argument("--claim", action="store_true",
                        help="actually claim (default: show address + limits only)")
    faucet.add_argument("--chat", action="store_true",
                        help="also post '!faucet request' to the flop-devnet-faucet room "
                             "(2 FLOP agent lane — see the warning)")
    faucet.add_argument("--dry-run", action="store_true",
                        help="print exactly what would be sent, send nothing")
    faucet.add_argument("--json", action="store_true", help="machine-readable output")
    faucet.add_argument("--client", default=FAUCET_CLIENT_LABEL,
                        help="telemetry label only; never changes limits or amount")
    faucet.add_argument("--key", type=Path, default=None)
    faucet.add_argument("--passphrase-file", type=Path,
                        help="read passphrase from FILE (headless/cron). WARNING: plaintext on disk — chmod 600, never commit!")

    bal = sub.add_parser(
        "balance",
        help="devnet FLOP balance of your DID's SS58 (or any SS58)",
        description=(
            "Read-only. Shows FREE / RESERVED / FROZEN on the FLOP devnet, so you "
            "can confirm a faucet grant actually landed instead of trusting a "
            "pending reply."
        ),
    )
    bal.add_argument("address", nargs="?", default=None,
                     help="SS58 address (default: the one derived from your DID)")
    bal.add_argument("--network", choices=FAUCET_NETWORKS,
                     default=FAUCET_DEFAULT_NETWORK,
                     help="which chain to read (default: testnet)")
    bal.add_argument("--json", action="store_true", help="machine-readable output")
    bal.add_argument("--key", type=Path, default=None)
    bal.add_argument("--passphrase-file", type=Path,
                     help="read passphrase from FILE (headless/cron). WARNING: plaintext on disk — chmod 600, never commit!")

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
        elif args.command == "faucet":
            key_path = resolve_key_path(args.key)
            pk = load_identity(key_path, passphrase=pphrase)
            did = did_from_private_key(pk)
            address = ss58_address_from_did(did)
            network = args.network

            if args.check:
                # Everything except the POST. A typo'd address or a wrong network
                # fails here instead of surfacing as a confusing claim error.
                checks = []
                try:
                    info = validate_ss58(address)
                    checks.append(("address checksum", True,
                                   f"{address[:8]}...{address[-6:]} "
                                   f"({len(bytes.fromhex(info['account']))} byte key)"))
                except ProtocolError as e:
                    checks.append(("address checksum", False, str(e)))
                try:
                    st = faucet_status(network)
                    checks.append(("network", st.get("network") == network,
                                   f"{st.get('network')} · {st.get('chain')}"))
                    checks.append(("genesis", bool(st.get("genesisHash")),
                                   str(st.get("genesisHash"))[:20] + "..."))
                    checks.append(("faucet open", st.get("faucetStatus") == "open",
                                   str(st.get("faucetStatus"))))
                except (ProtocolError, NetworkError) as e:
                    checks.append(("faucet reachable", False, str(e)[:80]))
                # Balance is INFORMATIONAL, not a gate: a wallet that has never
                # been funded is not on chain yet, which is the normal starting
                # state. Treating that as "not ready" would tell every new user
                # their install is broken.
                info_only = set()
                try:
                    bal = devnet_balance(address, network=network)
                    checks.append(("account on chain", True,
                                   f"{bal.get('free', 0)} FLOP" if bal["exists"]
                                   else "belum ada — normal, belum pernah dibayar"))
                    info_only.add("account on chain")
                except (ProtocolError, NetworkError) as e:
                    checks.append(("rpc reachable", False, str(e)[:80]))

                ok = all(v for n, v, _ in checks if n not in info_only)
                if args.json:
                    print(json.dumps({"network": network, "did": did, "ss58": address,
                                      "ready": ok,
                                      "checks": [{"name": n, "ok": v, "detail": d}
                                                 for n, v, d in checks]}, indent=2))
                else:
                    print(f"DID      {did}")
                    print(f"SS58     {address}")
                    print()
                    for n, v, d in checks:
                        mark = "OK  " if v else ("INFO" if n in info_only else "FAIL")
                        print(f"{mark}  {n:<20} {d}")
                    print()
                    print("READY — jalankan: faucet --claim" if ok else
                          "BELUM READY — perbaiki yang FAIL di atas dulu.")
                print()
                print("Catatan: faucet membatasi per-IP (ipGrantsPerDay, "
                      "ipCooldownSeconds). Di VPS/datacenter IP dipakai bersama, jadi "
                      "hasil bisa ip_cooldown walau semua cek di atas OK. Itu bukan "
                      "salah repo — coba dari IP lain atau tunggu cooldown habis.",
                      file=sys.stderr)
                return 0 if ok else 1
            if not args.claim:
                # Status only: show BOTH networks, because they are not the same
                # faucet and mixing them up is the usual mistake.
                rows = []
                for net in FAUCET_NETWORKS:
                    try:
                        rows.append((net, faucet_status(net)))
                    except (ProtocolError, NetworkError) as e:
                        rows.append((net, {"error": str(e)}))
                if args.json:
                    print(json.dumps({"did": did, "ss58": address,
                                      "networks": dict(rows)}, indent=2))
                else:
                    print(f"DID            {did}")
                    print(f"SS58 (own key) {address}")
                    print()
                    for net, info in rows:
                        if info.get("error"):
                            print(f"{net:<8} ERROR {info['error']}")
                            continue
                        print(f"{net:<8} {info.get('faucetStatus')} · "
                              f"{info.get('chain')} · grant "
                              f"{info.get('anonymousGrantFlop')} FLOP anon / "
                              f"{info.get('agentGrantFlop')} FLOP agent")
                    print()
                    print("Claim Testnet (10 FLOP, signed):  faucet --claim")
                    print("Claim Devnet  (25 FLOP, POST):    faucet --claim --network devnet")
                    print()
                    print("Why your DID has an address: the did:key IS an Ed25519 key, "
                          "and SS58 is that key plus a checksum. No second wallet needed.")
            elif network == "testnet":
                if args.dry_run:
                    info = faucet_status(network)
                    n = args.nonce or str(int(time.time() * 1000))
                    msg = faucet_agent_claim_message(info["genesisHash"], address, n)
                    print(json.dumps({
                        "network": network, "did": did, "ss58": address,
                        "nonce": n, "message_to_sign": msg,
                        "wouldPost": {"url": FAUCET_HOSTS[network] + FAUCET_AGENT_CLAIM_PATH,
                                      "body": {"address": address, "nonce": n,
                                               "signature": "0x<ed25519 of the message>"}},
                    }, indent=2))
                    print("dry run: nothing was sent.", file=sys.stderr)
                else:
                    status, out = faucet_agent_claim(
                        pk, address, nonce=args.nonce, network=network)
                    reply = out["reply"]
                    ok = bool(reply.get("success"))
                    if args.json:
                        print(json.dumps({"network": network, "httpStatus": status,
                                          **out}, indent=2))
                    else:
                        print(f"network  {network}")
                        print(f"DID      {did}")
                        print(f"SS58     {address}")
                        print(f"nonce    {out['request']['nonce']}")
                        if ok:
                            print(f"result   funded {reply.get('amount')} FLOP · "
                                  f"tx {reply.get('txHash')} · "
                                  f"status {reply.get('status')}")
                        else:
                            why = (reply.get("error") or reply.get("reason")
                                   or reply.get("raw")
                                   or f"unrecognised reply (HTTP {status})")
                            line = f"result   NOT funded — {why}"
                            if reply.get("reason") and reply.get("reason") not in str(why):
                                line += f" (reason={reply['reason']})"
                            print(line)
                    if not ok:
                        print(
                            "Not retried on purpose. Repeating the SAME nonce is the "
                            "documented way to re-check a request; a new nonce only "
                            "after the previous one reached a final result.",
                            file=sys.stderr)
                        return 1
            else:
                # Devnet: plain POST /fund, 25 FLOP, no signature.
                if args.dry_run:
                    info = faucet_status(network)
                    print(json.dumps({
                        "network": network, "did": did, "ss58": address,
                        "faucetStatus": info.get("faucetStatus"),
                        "wouldPost": {"url": f"{FAUCET_HOSTS[network]}/fund",
                                      "body": {"address": address,
                                               "client": args.client}},
                    }, indent=2))
                    print("dry run: nothing was sent.", file=sys.stderr)
                else:
                    if faucet_status(network).get("faucetStatus") != "open":
                        raise NetworkError("devnet faucet is not open right now")
                    result = faucet_claim(address, client=args.client,
                                          network=network)
                    ok, line = describe_faucet_outcome(result, address)
                    if args.json:
                        print(json.dumps({"network": network, "funded": ok,
                                          "reply": result}, indent=2))
                    else:
                        print(f"network  {network}")
                        print(f"DID      {did}")
                        print(f"SS58     {address}")
                        print(f"result   {line}")
                    if not ok:
                        print(
                            "Not retried on purpose: a refusal is final until the "
                            "stated wait passes.", file=sys.stderr)
                        return 1
        elif args.command == "balance":
            address = args.address
            if address is None:
                pk = load_identity(resolve_key_path(args.key), passphrase=pphrase)
                address = ss58_address_from_did(did_from_private_key(pk))
            info = devnet_balance(address, network=args.network)
            if args.json:
                print(json.dumps(info, indent=2))
            else:
                print(f"address  {info['address']}")
                print(f"network  {args.network}")
                print(f"block    {info.get('block')}")
                if not info["exists"]:
                    print("balance  akun belum ada di chain — grant biasanya masih "
                          "antre di faucet (cek /limits -> pendingGrants)")
                else:
                    print(f"FREE     {info['free']} FLOP")
                    print(f"RESERVED {info['reserved']} FLOP")
                    print(f"FROZEN   {info['frozen']} FLOP")
                    print(f"nonce    {info['nonce']} · providers {info['providers']}")
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
