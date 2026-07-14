"""
Zoning -- end-to-end demonstration.

Domain-neutral on purpose: the mutation here is a payroll change, but it could
be a funds transfer, a medical-record update, a production config change, or
an IAM role grant. Zoning does not care what the mutation is -- only that no
layer performs it without proof.

Run:  python demo.py
"""
from zoning import (
    ConsumedRegistry, Device, Verifier,
    ZoningError, layer_check,
)

verifier = Verifier()
final_gate = ConsumedRegistry()
PROOF_KEY = verifier.proof_key  # distributed to each service at deploy time


def write_path(payload: dict, token: str | None) -> str:
    """Three independent hops. Each verifies the proof STATELESSLY --
    no shared store between them. The final gate adds single-use."""
    if token is None:
        raise ZoningError("no proof presented")
    layer_check("api-gateway", token, payload, PROOF_KEY)
    layer_check("domain-service", token, payload, PROOF_KEY)
    claims = layer_check("system-of-record-adapter", token, payload, PROOF_KEY)
    final_gate.consume(claims["proof_id"])       # Posture B single-use gate
    return f"MUTATION APPLIED (proof {claims['proof_id'][:8]}..., approved by {claims['user_id']})"


print("\n=== ZONING v2 -- COMPLETE FLOW (Python) ===\n")

# 1. Enrollment (once, inside an authenticated session)
alice_device = Device("alice")
verifier.enroll_device(alice_device.device_id, "alice", alice_device.public_key_pem)
print(f"1. Device enrolled for alice: {alice_device.device_id[:8]}...")

# 2. Alice initiates a sensitive mutation
payload = {"action": "update_salary", "employee": "E-1042",
           "new_salary": 95000, "meta": {"reason": "promotion"}}
print(f"2. Mutation initiated: {payload}")

# 3. Server issues a challenge bound to the canonical payload
ch = verifier.issue_challenge(alice_device.device_id, payload)
print(f"3. Challenge issued: {ch.nonce[:16]}... (ttl 60s)")

# 4-5. Device shows the summary, Alice confirms (biometric), device signs
signature = alice_device.sign(Verifier.signing_message(payload, ch.nonce, alice_device.device_id))
print("4. Alice confirms on-device -> signature produced")

# 6. Verifier checks everything, burns the challenge, mints the proof
token = verifier.verify_and_mint(alice_device.device_id, payload, ch.nonce, signature)
print(f"5. Proof minted ({len(token)} bytes) -- travels as one header")

# 7. The write path: every hop verifies independently
print("6.", write_path(payload, token))

print("\n=== ATTACK DEMONSTRATIONS ===\n")

def attack(name: str, fn):
    try:
        fn()
        print(f"[FAILURE] {name} succeeded (must never happen)")
    except ZoningError as e:
        print(f"[BLOCKED] {name}: {e}")

# A. Replay: reuse the same proof for a second mutation
attack("replay of a consumed proof", lambda: write_path(payload, token))

# B. Tampering: valid-looking request, nested field altered after approval
tampered = {**payload, "meta": {"reason": "promotion", "override": True}}
attack("nested payload tampering", lambda: write_path(tampered, token))

# C. Bypass: internal caller hits the system of record with no proof
attack("no-proof internal write", lambda: write_path({"action": "grant_admin", "to": "mallory"}, None))

# D. Forgery: attacker mints their own 'proof' without the key
from zoning import mint_proof
import time as _t
forged = mint_proof({"proof_id": "x", "payload_hash": "y", "device_id": "z",
                     "user_id": "mallory", "iat": _t.time(), "exp": _t.time() + 60}, b"wrong-key")
attack("forged proof (wrong key)", lambda: write_path(payload, forged))

# E. Stolen session: attacker has alice's SESSION but not her DEVICE --
#    they can request a challenge, but cannot produce her signature.
mallory_device = Device("mallory-posing-as-alice")   # not enrolled for alice
ch2 = verifier.issue_challenge(alice_device.device_id, payload)
bad_sig = mallory_device.sign(Verifier.signing_message(payload, ch2.nonce, alice_device.device_id))
attack("stolen session, wrong device key",
       lambda: verifier.verify_and_mint(alice_device.device_id, payload, ch2.nonce, bad_sig))

# F. Revoked device: alice reports her phone stolen
verifier.revoke_device(alice_device.device_id)
ch3 = verifier.issue_challenge(alice_device.device_id, payload)
sig3 = alice_device.sign(Verifier.signing_message(payload, ch3.nonce, alice_device.device_id))
attack("revoked device", lambda: verifier.verify_and_mint(alice_device.device_id, payload, ch3.nonce, sig3))

print("\n=== SUMMARY ===")
print("OK: Zone 1: device enrolled inside an authenticated session")
print("OK: Zone 2: mutation approved on-device, bound to exact payload")
print("OK: Every hop verified the proof independently and statelessly")
print("OK: Single-use enforced at the innermost gate")
print("OK: Replay / tampering / bypass / forgery / stolen-session / revoked-device: all refused\n")
