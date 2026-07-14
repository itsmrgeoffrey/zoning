"""
Zoning — bound mutation authorization.

Zone 1 (access) proves who is connected: your existing login. Zoning does not
replace it. Zone 2 (mutation authority) proves that a SPECIFIC state change was
approved by a SPECIFIC human on a SPECIFIC enrolled device — per operation,
bound to the exact payload, single-use, and independently verifiable by every
service the request passes through.

A stolen session can read. It cannot mutate, because it cannot produce a
Zone 2 proof.

Design constraints (deliberate):
- No custom client cryptography: devices sign with platform keystores
  (Secure Enclave / Android Keystore / WebAuthn). The Device class here only
  SIMULATES that for the demo and tests.
- One server-side component (the Verifier) plus a challenge store.
- Downstream services verify a compact HMAC-signed proof STATELESSLY —
  no shared database between layers.
- Single-use is enforced at the innermost gate you control: a UNIQUE
  constraint if you own the datastore, or the atomic ConsumedRegistry here
  if you don't.

This file is the complete reference implementation. Stdlib except for
`cryptography` (device keys, P-256).
"""
from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import json
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# ─────────────────────────────────────────────────────────────────────────────
# Canonicalization
#
# The payload must hash identically wherever it is inspected. json.dumps with
# sort_keys=True is RECURSIVE, so nested fields are fully covered by the hash
# (a top-level-only key sort would let nested fields escape integrity
# protection). For single-language deployments this is sufficient; for
# cross-language deployments use full RFC 8785 (JCS) so number formatting
# matches everywhere.
# ─────────────────────────────────────────────────────────────────────────────

def canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def payload_hash(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Errors — one type per rejection reason, so callers can log precisely.
# ─────────────────────────────────────────────────────────────────────────────

class ZoningError(Exception):
    """Base class: any reason a mutation must be refused."""


class ChallengeNotFound(ZoningError): ...
class ChallengeExpired(ZoningError): ...
class ChallengeConsumed(ZoningError): ...
class PayloadMismatch(ZoningError): ...
class DeviceUnknown(ZoningError): ...
class DeviceRevoked(ZoningError): ...
class BadSignature(ZoningError): ...
class ProofInvalid(ZoningError): ...
class ProofExpired(ZoningError): ...
class ProofAlreadyUsed(ZoningError): ...


# ─────────────────────────────────────────────────────────────────────────────
# Device (CLIENT-SIDE SIMULATION)
#
# In production this is the platform keystore: the private key is generated
# inside Secure Enclave / Android Keystore / a WebAuthn authenticator and can
# never be exported. Signing is gated by the platform's biometric/PIN prompt.
# ─────────────────────────────────────────────────────────────────────────────

class Device:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.device_id = str(uuid.uuid4())
        self._private_key = ec.generate_private_key(ec.SECP256R1())

    @property
    def public_key_pem(self) -> str:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def sign(self, message: bytes) -> bytes:
        """In production: preceded by the OS biometric/PIN prompt showing the
        human-readable summary of the mutation being approved."""
        return self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))


# ─────────────────────────────────────────────────────────────────────────────
# Challenge store
#
# In-memory with a lock for the reference implementation. In production use
# Redis: SET NX for issue, and an atomic GETDEL / Lua compare-and-set for the
# burn. The property that matters is that consume() is ATOMIC — two racing
# requests can never both pass.
# ─────────────────────────────────────────────────────────────────────────────

CHALLENGE_TTL_SECONDS = 60


@dataclass
class Challenge:
    nonce: str
    device_id: str
    payload_hash: str
    issued_at: float
    expires_at: float
    status: str = "pending"  # pending | consumed


class ChallengeStore:
    def __init__(self):
        self._store: dict[str, Challenge] = {}
        self._lock = threading.Lock()

    def put(self, ch: Challenge) -> None:
        with self._lock:
            self._store[ch.nonce] = ch

    def consume(self, nonce: str) -> Challenge:
        """Atomically fetch-and-burn. Raises if missing/expired/already used."""
        with self._lock:
            ch = self._store.get(nonce)
            if ch is None:
                raise ChallengeNotFound("challenge not found")
            if ch.status != "pending":
                raise ChallengeConsumed("challenge already consumed (replay?)")
            if time.time() > ch.expires_at:
                del self._store[nonce]
                raise ChallengeExpired("challenge expired")
            ch.status = "consumed"
            return ch


# ─────────────────────────────────────────────────────────────────────────────
# Mutation proof
#
# What the Verifier mints after a device signature checks out, and what every
# downstream service verifies STATELESSLY: base64url(claims JSON) + "." +
# base64url(HMAC-SHA256 over the encoded claims). ~200 bytes; travels as one
# header (e.g. X-Zoning-Proof).
#
# HMAC keeps the reference light (one shared verification key). If untrusted
# parties must verify but never mint, swap the HMAC for an asymmetric
# signature — the claims format does not change.
# ─────────────────────────────────────────────────────────────────────────────

PROOF_TTL_SECONDS = 120


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint_proof(claims: dict, key: bytes) -> str:
    body = _b64u(canonical_json(claims).encode())
    sig = hmac_mod.new(key, body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64u(sig)}"


def verify_proof(token: str, payload: dict, key: bytes) -> dict:
    """The per-layer check. Stateless: signature + expiry + payload binding.
    ~three comparisons; no I/O; no shared store."""
    try:
        body, sig = token.split(".")
        expected = hmac_mod.new(key, body.encode(), hashlib.sha256).digest()
        if not hmac_mod.compare_digest(_b64u_decode(sig), expected):
            raise ProofInvalid("proof signature invalid")
        claims = json.loads(_b64u_decode(body))
    except ProofInvalid:
        raise
    except Exception as exc:  # malformed token, bad base64, bad JSON
        raise ProofInvalid(f"malformed proof: {exc}") from exc

    if time.time() > claims.get("exp", 0):
        raise ProofExpired("proof expired")
    if claims.get("payload_hash") != payload_hash(payload):
        raise PayloadMismatch("payload does not match the approved mutation")
    return claims


# ─────────────────────────────────────────────────────────────────────────────
# Verifier — the one new server-side component.
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EnrolledDevice:
    device_id: str
    user_id: str
    public_key_pem: str
    active: bool = True
    enrolled_at: float = field(default_factory=time.time)


class Verifier:
    def __init__(self, proof_key: bytes | None = None):
        self.proof_key = proof_key or secrets.token_bytes(32)
        self.devices: dict[str, EnrolledDevice] = {}
        self.challenges = ChallengeStore()

    # -- Zone 1: enrollment (MUST happen inside an authenticated session) ----

    def enroll_device(self, device_id: str, user_id: str, public_key_pem: str) -> None:
        self.devices[device_id] = EnrolledDevice(device_id, user_id, public_key_pem)

    def revoke_device(self, device_id: str) -> None:
        if device_id in self.devices:
            self.devices[device_id].active = False

    # -- Zone 2: challenge → signature → proof --------------------------------

    def issue_challenge(self, device_id: str, payload: dict) -> Challenge:
        """Server-random nonce (the client never chooses its own), bound to
        the canonical payload hash and this device, short TTL."""
        now = time.time()
        ch = Challenge(
            nonce=secrets.token_hex(32),
            device_id=device_id,
            payload_hash=payload_hash(payload),
            issued_at=now,
            expires_at=now + CHALLENGE_TTL_SECONDS,
        )
        self.challenges.put(ch)
        return ch

    @staticmethod
    def signing_message(payload: dict, nonce: str, device_id: str) -> bytes:
        """Exactly what the device signs: payload bound to nonce and device."""
        return f"{canonical_json(payload)}|{nonce}|{device_id}".encode()

    def verify_and_mint(self, device_id: str, payload: dict, nonce: str, signature: bytes) -> str:
        """The heart of Zoning. Checks in order, burns the challenge
        atomically, then mints the proof downstream layers will verify."""
        device = self.devices.get(device_id)
        if device is None:
            raise DeviceUnknown("device not enrolled")
        if not device.active:
            raise DeviceRevoked("device has been revoked")

        # Atomic: no two requests can both consume the same challenge.
        ch = self.challenges.consume(nonce)

        if ch.device_id != device_id:
            raise PayloadMismatch("challenge was issued to a different device")
        if ch.payload_hash != payload_hash(payload):
            raise PayloadMismatch("payload does not match the challenged mutation")

        public_key = serialization.load_pem_public_key(device.public_key_pem.encode())
        try:
            public_key.verify(
                signature,
                self.signing_message(payload, nonce, device_id),
                ec.ECDSA(hashes.SHA256()),
            )
        except InvalidSignature as exc:
            raise BadSignature("device signature invalid") from exc

        now = time.time()
        claims = {
            "proof_id": str(uuid.uuid4()),
            "payload_hash": ch.payload_hash,
            "device_id": device_id,
            "user_id": device.user_id,
            "iat": now,
            "exp": now + PROOF_TTL_SECONDS,
        }
        return mint_proof(claims, self.proof_key)


# ─────────────────────────────────────────────────────────────────────────────
# Final gate — single use.
#
# Posture A (you own the datastore): put a UNIQUE(proof_id) constraint on the
#   mutation/journal table and store the proof columns. The database refuses
#   the second write; nothing here is needed.
# Posture B (you cannot touch the datastore): the innermost service you DO
#   control consumes the proof_id here (atomic), then performs the mutation.
# ─────────────────────────────────────────────────────────────────────────────

class ConsumedRegistry:
    def __init__(self):
        self._used: dict[str, float] = {}
        self._lock = threading.Lock()

    def consume(self, proof_id: str) -> None:
        with self._lock:
            if proof_id in self._used:
                raise ProofAlreadyUsed("proof already consumed (replay blocked)")
            self._used[proof_id] = time.time()


def layer_check(name: str, token: str, payload: dict, key: bytes) -> dict:
    """What every hop on the write path runs. Verify → proceed; fail → refuse.
    Identical at the gateway, mid-tier services, and the final gate."""
    claims = verify_proof(token, payload, key)
    return claims
