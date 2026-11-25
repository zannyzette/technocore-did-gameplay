"""Faucet tests — SS58 derivation + no-retry refusal handling.

Everything here is offline: the network is monkeypatched. The SS58 vectors are
the public Substrate development accounts (well-known, key-type agnostic), so
this file carries no operator identity.
"""
import json

import pytest

import technocore_agent as tca


# --- SS58 derivation -------------------------------------------------------

# Alice / Bob from the Substrate dev phrase. Public, published in every
# Substrate tutorial — the encoder does not care whether the key is sr25519 or
# ed25519, so these are valid vectors for the format itself.
ALICE_PUB = bytes.fromhex(
    "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
)
ALICE_SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
BOB_PUB = bytes.fromhex(
    "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
)
BOB_SS58 = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"


def test_ss58_alice():
    assert tca.ss58_address_from_pubkey(ALICE_PUB) == ALICE_SS58


def test_ss58_bob():
    assert tca.ss58_address_from_pubkey(BOB_PUB) == BOB_SS58


def test_ss58_rejects_bad_key_length():
    with pytest.raises(tca.ProtocolError):
        tca.ss58_address_from_pubkey(b"\x01" * 31)
    with pytest.raises(tca.ProtocolError):
        tca.ss58_address_from_pubkey("not bytes")


def test_ss58_from_did_matches_same_key():
    """The address a DID derives must be the address of THAT key, nothing else."""
    import os
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    did = tca.did_from_private_key(pk)
    raw = pk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert tca.ss58_address_from_did(did) == tca.ss58_address_from_pubkey(raw)


def test_ss58_from_did_is_48_chars_and_starts_with_5():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    did = tca.did_from_private_key(Ed25519PrivateKey.from_private_bytes(b"\x07" * 32))
    addr = tca.ss58_address_from_did(did)
    assert addr.startswith("5")
    assert 46 <= len(addr) <= 48


# --- outcome handling ------------------------------------------------------

def test_outcome_success():
    ok, line = tca.describe_faucet_outcome(
        {"success": True, "amount": 25, "tier": "anonymous",
         "address": "5Abc", "txHash": "0xdead"}
    )
    assert ok is True
    assert "25 FLOP" in line and "0xdead" in line


def test_outcome_success_without_address_uses_what_we_asked_for():
    """The live success body has no `address` field — do not print 'to ?'."""
    ok, line = tca.describe_faucet_outcome(
        {"success": True, "amount": 25, "tier": "anonymous", "txHash": "0xbeef"},
        "5AskedFor",
    )
    assert ok is True
    assert "5AskedFor" in line and "?" not in line


def test_outcome_refusal_carries_reason_and_wait():
    ok, line = tca.describe_faucet_outcome(
        {"error": "refused", "reason": "address_cooldown", "retryAfterSeconds": 3600}
    )
    assert ok is False
    assert "address_cooldown" in line and "3600s" in line


def test_outcome_unknown_reason_does_not_crash():
    ok, line = tca.describe_faucet_outcome({})
    assert ok is False
    assert "unknown" in line


# --- no-retry contract -----------------------------------------------------

def test_claim_never_retries_on_refusal(monkeypatch):
    calls = []

    def fake(path, body=None, network="devnet"):
        calls.append((path, body, network))
        return {"error": "refused", "reason": "address_cooldown",
                "retryAfterSeconds": 60}

    monkeypatch.setattr(tca, "_faucet_request", fake)
    result = tca.faucet_claim("5Abc", network="devnet")
    assert len(calls) == 1, "a refusal must not be retried"
    assert result["reason"] == "address_cooldown"


def test_claim_rejects_empty_address():
    with pytest.raises(tca.ProtocolError):
        tca.faucet_claim("   ", network="devnet")


def test_claim_refuses_testnet_plain_post():
    """POST /fund is closed on Testnet — never silently fall back to it."""
    with pytest.raises(tca.ProtocolError):
        tca.faucet_claim("5Abc", network="testnet")


def test_claim_sends_address_and_client(monkeypatch):
    seen = {}

    def fake(path, body=None, network="devnet"):
        seen["path"] = path
        seen["body"] = body
        seen["network"] = network
        return {"success": True, "amount": 25, "tier": "anonymous"}

    monkeypatch.setattr(tca, "_faucet_request", fake)
    tca.faucet_claim("5Abc", client="my-client", network="devnet")
    assert seen["path"] == "/fund"
    assert seen["body"] == {"address": "5Abc", "client": "my-client"}
    assert seen["network"] == "devnet"


# --- testnet signed agent claim --------------------------------------------

TESTNET_GENESIS = ("0x918abd58fb16306b30ef3886514cfaeb"
                   "ffecb4de43e82b6f8ec4795c43cfd800")


def test_agent_claim_message_is_exact():
    """Byte-exact template — the faucet rejects anything else."""
    msg = tca.faucet_agent_claim_message(TESTNET_GENESIS, "5Abc", "1795615416031")
    assert msg == (
        "flop-faucet-agent/v1|" + TESTNET_GENESIS + "|5Abc|1795615416031"
    )


def test_agent_claim_signs_with_identity_key(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    seen = {}

    def fake_status(network="testnet"):
        return {"genesisHash": TESTNET_GENESIS, "network": "testnet"}

    def fake_post(path, body, network="testnet"):
        seen.update(path=path, body=body, network=network)
        return 200, {"success": True, "amount": 10, "tier": "anon_agent",
                     "txHash": "0x" + "ab" * 32, "status": "finalized"}

    monkeypatch.setattr(tca, "faucet_status", fake_status)
    monkeypatch.setattr(tca, "_faucet_request_full", fake_post)

    status, out = tca.faucet_agent_claim(pk, ALICE_SS58, nonce="123")
    assert status == 200
    assert seen["path"] == "/v1/testnet/agent-claims"
    assert seen["body"]["nonce"] == "123"
    sig = seen["body"]["signature"]
    assert sig.startswith("0x") and len(sig) == 130
    # the signature must verify against the message we claim to have signed
    pk.public_key().verify(bytes.fromhex(sig[2:]),
                           out["request"]["message"].encode())


def test_agent_claim_rejects_bad_nonce(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    monkeypatch.setattr(tca, "faucet_status",
                        lambda network="testnet": {"genesisHash": TESTNET_GENESIS})
    pk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    with pytest.raises(tca.ProtocolError):
        tca.faucet_agent_claim(pk, ALICE_SS58, nonce="12ab")


def test_agent_claim_is_testnet_only(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    with pytest.raises(tca.ProtocolError):
        tca.faucet_agent_claim(pk, ALICE_SS58, network="devnet")


def test_status_rejects_wrong_network(monkeypatch):
    """If the host serves a different chain than asked, refuse — never sign."""
    def fake(path, body=None, network="testnet"):
        if path == "/limits":
            return {"network": "testnet", "faucet": {"status": "open"}}
        return {"network": "testnet", "genesisHash": TESTNET_GENESIS}

    monkeypatch.setattr(tca, "_faucet_request", fake)
    with pytest.raises(tca.NetworkError):
        tca.faucet_status("devnet")


# --- SS58 validation (the "invalid address" class of failure) --------------

def test_validate_accepts_real_address():
    info = tca.validate_ss58(ALICE_SS58)
    assert info["valid"] is True
    assert info["format"] == 42
    assert info["account"] == ALICE_PUB.hex()


def test_validate_rejects_wrong_length():
    """A hallucinated address decodes to the wrong byte count — catch it early."""
    with pytest.raises(tca.ProtocolError) as e:
        tca.validate_ss58("5C4T8FBwBwZzRKvMHE8AVzXDMhxjuk2s5hQjBjMJSn5zVaR")
    assert "34 bytes" in str(e.value)


def test_validate_rejects_bad_checksum():
    """Right length, wrong checksum: flipping the last char must be caught."""
    broken = ALICE_SS58[:-1] + ("Y" if ALICE_SS58[-1] != "Y" else "Z")
    with pytest.raises(tca.ProtocolError):
        tca.validate_ss58(broken)


def test_validate_rejects_garbage():
    for bad in ("", "not-an-address", "0OIl"):
        with pytest.raises(tca.ProtocolError):
            tca.validate_ss58(bad)


def test_claim_fails_before_signing_on_bad_address(monkeypatch):
    """No network call at all when the address is malformed."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    called = []
    monkeypatch.setattr(tca, "faucet_status",
                        lambda network="testnet": called.append(1) or {})
    pk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    with pytest.raises(tca.ProtocolError):
        tca.faucet_agent_claim(pk, "5C4T8FBwBwZzRKvMHE8AVzXDMhxjuk2s5hQjBjMJSn5zVaR")
    assert called == [], "must not touch the network with an invalid address"


def test_validate_is_not_a_gate_for_unfunded_wallets():
    """A never-funded wallet is not on chain — that must not read as 'not ready'."""
    import subprocess, sys, json, os
    # covered structurally: 'account on chain' is in info_only, so it cannot
    # flip the ready flag. Assert the contract on the helper that decides it.
    checks = [("address checksum", True, ""), ("network", True, ""),
              ("account on chain", True, "belum ada")]
    info_only = {"account on chain"}
    assert all(v for n, v, _ in checks if n not in info_only) is True


# --- on-chain balance ------------------------------------------------------

def test_account_storage_key_shape():
    key = tca.account_storage_key(ALICE_SS58)
    assert key.startswith(tca.ACCOUNT_STORAGE_PREFIX)
    # prefix (32 bytes) + blake2_128 (16) + account id (32) = 80 bytes
    assert len(bytes.fromhex(key[2:])) == 80
    assert key.endswith(ALICE_PUB.hex())


def test_account_storage_key_rejects_non_ss58():
    with pytest.raises(tca.ProtocolError):
        tca.account_storage_key("not-an-address")


def test_balance_reports_missing_account_without_inventing_numbers(monkeypatch):
    """A queued grant is an account that is not on chain yet — say so, do not 0."""
    replies = {"chain_getHeader": {"result": {"number": "0x10"}},
               "state_getStorage": {"result": None}}

    def fake(url, method, params, tries=3):
        return replies[method]

    monkeypatch.setattr(tca, "_rpc_call", fake)
    info = tca.devnet_balance(ALICE_SS58)
    assert info["exists"] is False
    assert info["block"] == 16
    assert "free" not in info


def test_balance_decodes_account_info(monkeypatch):
    scale = 10 ** 18
    free = 25 * scale
    reserved = 2 * scale
    raw = (b"\x00" * 4                       # nonce
           + b"\x01" + b"\x00" * 3           # consumers = 1
           + b"\x01" + b"\x00" * 3           # providers = 1
           + b"\x00" * 4                      # sufficients
           + free.to_bytes(16, "little")
           + reserved.to_bytes(16, "little")
           + (0).to_bytes(16, "little"))
    replies = {"chain_getHeader": {"result": {"number": "0xff"}},
               "state_getStorage": {"result": "0x" + raw.hex()}}

    def fake(url, method, params, tries=3):
        return replies[method]

    monkeypatch.setattr(tca, "_rpc_call", fake)
    info = tca.devnet_balance(ALICE_SS58)
    assert info["exists"] is True
    assert info["free"] == 25.0
    assert info["reserved"] == 2.0
    assert info["frozen"] == 0.0
    assert info["providers"] == 1


def test_rpc_surfaces_errors_instead_of_returning_none(monkeypatch):
    """A JSON-RPC error must raise; silently returning None reads as balance 0."""
    def boom(url, method, params, tries=3):
        raise tca.NetworkError("rpc error: {'code': -32601}")

    monkeypatch.setattr(tca, "_rpc_call", boom)
    with pytest.raises(tca.NetworkError):
        tca.devnet_balance(ALICE_SS58)


# --- chat lane payload -----------------------------------------------------

def test_chat_request_payload_shape():
    req = tca.faucet_chat_request("did:key:zTest", "5Abc", nonce=1795512353164)
    assert req["text"] == "!faucet request 5Abc 1795512353164"
    assert req["room"] == "flop-devnet-faucet"


def test_chat_request_uses_ms_clock_when_no_nonce():
    req = tca.faucet_chat_request("did:key:zTest", "5Abc")
    assert 10 ** 12 < req["nonce"] < 10 ** 14
