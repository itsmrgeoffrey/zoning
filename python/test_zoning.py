"""Security properties under test — each test is one attack that must fail,
or one legitimate flow that must succeed."""
import time

import pytest

from zoning import (
    BadSignature, ChallengeConsumed, ChallengeExpired, ChallengeNotFound,
    ConsumedRegistry, Device, DeviceRevoked, DeviceUnknown, PayloadMismatch,
    ProofAlreadyUsed, ProofExpired, ProofInvalid, Verifier,
    canonical_json, mint_proof, payload_hash, verify_proof,
)

PAYLOAD = {"action": "transfer", "amount": 100, "to": "bob", "meta": {"note": "rent"}}


@pytest.fixture()
def setup():
    verifier = Verifier()
    device = Device("alice")
    verifier.enroll_device(device.device_id, "alice", device.public_key_pem)
    return verifier, device


def _approve(verifier, device, payload):
    ch = verifier.issue_challenge(device.device_id, payload)
    sig = device.sign(Verifier.signing_message(payload, ch.nonce, device.device_id))
    return verifier.verify_and_mint(device.device_id, payload, ch.nonce, sig)


# ─── Canonicalization ────────────────────────────────────────────────────────

def test_canonicalization_is_recursive():
    a = {"z": 1, "a": {"y": 2, "b": 3}}
    b = {"a": {"b": 3, "y": 2}, "z": 1}
    assert canonical_json(a) == canonical_json(b)


def test_nested_fields_are_integrity_protected():
    """Nested fields must be covered by the payload hash (a top-level-only
    key sort would let them escape integrity protection)."""
    base = {"amount": 100, "meta": {"note": "rent"}}
    tampered = {"amount": 100, "meta": {"note": "RENT-CHANGED"}}
    assert payload_hash(base) != payload_hash(tampered)


# ─── Happy path ──────────────────────────────────────────────────────────────

def test_full_flow_produces_verifiable_proof(setup):
    verifier, device = setup
    token = _approve(verifier, device, PAYLOAD)
    claims = verify_proof(token, PAYLOAD, verifier.proof_key)
    assert claims["user_id"] == "alice"
    assert claims["payload_hash"] == payload_hash(PAYLOAD)


def test_proof_verifies_statelessly_at_every_layer(setup):
    verifier, device = setup
    token = _approve(verifier, device, PAYLOAD)
    for _ in range(3):  # gateway, mid-tier, adapter — same check, no shared state
        assert verify_proof(token, PAYLOAD, verifier.proof_key)["user_id"] == "alice"


# ─── Challenge attacks ───────────────────────────────────────────────────────

def test_unknown_challenge_rejected(setup):
    verifier, device = setup
    sig = device.sign(b"whatever")
    with pytest.raises(ChallengeNotFound):
        verifier.verify_and_mint(device.device_id, PAYLOAD, "no-such-nonce", sig)


def test_challenge_single_use(setup):
    verifier, device = setup
    ch = verifier.issue_challenge(device.device_id, PAYLOAD)
    sig = device.sign(Verifier.signing_message(PAYLOAD, ch.nonce, device.device_id))
    verifier.verify_and_mint(device.device_id, PAYLOAD, ch.nonce, sig)
    with pytest.raises(ChallengeConsumed):
        verifier.verify_and_mint(device.device_id, PAYLOAD, ch.nonce, sig)


def test_challenge_expiry(setup, monkeypatch):
    verifier, device = setup
    ch = verifier.issue_challenge(device.device_id, PAYLOAD)
    sig = device.sign(Verifier.signing_message(PAYLOAD, ch.nonce, device.device_id))
    monkeypatch.setattr(time, "time", lambda: ch.expires_at + 1)
    with pytest.raises(ChallengeExpired):
        verifier.verify_and_mint(device.device_id, PAYLOAD, ch.nonce, sig)


def test_payload_swap_after_challenge_rejected(setup):
    verifier, device = setup
    ch = verifier.issue_challenge(device.device_id, PAYLOAD)
    evil = {**PAYLOAD, "to": "mallory"}
    sig = device.sign(Verifier.signing_message(evil, ch.nonce, device.device_id))
    with pytest.raises(PayloadMismatch):
        verifier.verify_and_mint(device.device_id, evil, ch.nonce, sig)


# ─── Device attacks ──────────────────────────────────────────────────────────

def test_unenrolled_device_rejected():
    verifier = Verifier()
    device = Device("mallory")
    ch_sig = device.sign(b"x")
    with pytest.raises(DeviceUnknown):
        verifier.verify_and_mint(device.device_id, PAYLOAD, "nonce", ch_sig)


def test_wrong_device_key_rejected(setup):
    verifier, device = setup
    imposter = Device("imposter")
    ch = verifier.issue_challenge(device.device_id, PAYLOAD)
    bad = imposter.sign(Verifier.signing_message(PAYLOAD, ch.nonce, device.device_id))
    with pytest.raises(BadSignature):
        verifier.verify_and_mint(device.device_id, PAYLOAD, ch.nonce, bad)


def test_revoked_device_rejected(setup):
    verifier, device = setup
    verifier.revoke_device(device.device_id)
    ch = verifier.issue_challenge(device.device_id, PAYLOAD)
    sig = device.sign(Verifier.signing_message(PAYLOAD, ch.nonce, device.device_id))
    with pytest.raises(DeviceRevoked):
        verifier.verify_and_mint(device.device_id, PAYLOAD, ch.nonce, sig)


# ─── Proof attacks ───────────────────────────────────────────────────────────

def test_tampered_payload_fails_at_layer(setup):
    verifier, device = setup
    token = _approve(verifier, device, PAYLOAD)
    tampered = {**PAYLOAD, "meta": {"note": "rent", "extra": True}}
    with pytest.raises(PayloadMismatch):
        verify_proof(token, tampered, verifier.proof_key)


def test_forged_proof_rejected(setup):
    verifier, _ = setup
    forged = mint_proof(
        {"proof_id": "f", "payload_hash": payload_hash(PAYLOAD),
         "device_id": "d", "user_id": "mallory",
         "iat": time.time(), "exp": time.time() + 60},
        b"attacker-key",
    )
    with pytest.raises(ProofInvalid):
        verify_proof(forged, PAYLOAD, verifier.proof_key)


def test_garbage_proof_rejected(setup):
    verifier, _ = setup
    with pytest.raises(ProofInvalid):
        verify_proof("not-a-proof", PAYLOAD, verifier.proof_key)


def test_expired_proof_rejected(setup, monkeypatch):
    verifier, device = setup
    token = _approve(verifier, device, PAYLOAD)
    monkeypatch.setattr(time, "time", lambda: time.mktime(time.gmtime()) + 10_000)
    with pytest.raises(ProofExpired):
        verify_proof(token, PAYLOAD, verifier.proof_key)


# ─── Final gate ──────────────────────────────────────────────────────────────

def test_final_gate_single_use(setup):
    verifier, device = setup
    token = _approve(verifier, device, PAYLOAD)
    claims = verify_proof(token, PAYLOAD, verifier.proof_key)
    gate = ConsumedRegistry()
    gate.consume(claims["proof_id"])
    with pytest.raises(ProofAlreadyUsed):
        gate.consume(claims["proof_id"])
