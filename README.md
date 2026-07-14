# zoning

**A cryptographic framework for authorizing critical state changes** — so that a
valid session, by itself, can never change anything that matters.

## Overview

ZONING enforces **cryptographic proof** of identity and **single-use, per-operation
confirmation** before any critical state change (a *mutation*) is executed.

Most systems today assume that a valid session (JWT, OAuth, API key) is sufficient
proof that a user intended an action. ZONING rejects that assumption. It introduces
a three-zone model where **authentication grants access only**, and each irreversible
mutation requires a **fresh, verifiable proof that a logged-in human actively
confirmed that exact change on their enrolled device**.

A mutation MUST NOT execute unless all required zones succeed.

The flagship application is **financial transactions** — transfers, beneficiary
changes, limit increases — where the cost of an unauthorized change is highest. But
the model is domain-neutral: the protected mutation can equally be a payroll bank-detail
change, an IAM role grant, a medical-record amendment, or a production config change.
ZONING does not care what the mutation is — only that no layer performs it without proof.

---

## The Problem

Current architectures rely on session-based trust:

- User authenticates
- Session token is issued
- Any request carrying that token is treated as intentional

This model cannot cryptographically guarantee:
- which device initiated a mutation
- what exact payload the user approved
- whether the change was actively confirmed at execution time

Which leaves the door open to:
- session replay / token theft
- payload tampering
- device impersonation
- partner- or integration-initiated unauthorized changes
- internal service abuse (a caller reaching an inner service directly)

ZONING addresses this gap by removing sessions as a source of authority to mutate.

---

## ZONING Architecture

ZONING is organized into three zones. Authentication grants access only; each
irreversible mutation requires its own fresh, single-use proof.

- **Zone 1 — Identity & Access.** A device keypair is generated in the platform
  keystore (Secure Enclave / Android Keystore / WebAuthn) and its public key
  registered to the user. Grants access, never authority to mutate.
- **Zone 2 — Mutation Confirmation.** For each mutation the backend issues a
  challenge bound to the exact (canonical) payload; the device signs it only after
  a live, blocking user confirmation (biometric/PIN), producing a single-use
  Attempt Receipt. The verifier then mints a compact, signed **proof**.
- **Zone 3 — Execution.** The mutation executes only after a valid proof is
  verified and consumed exactly once — at the **innermost execution gate the
  operator controls**.

Every service on the write path verifies the proof **statelessly** (signature +
payload-hash comparison), so the interior of the system stops implicitly trusting
the interior.

**The proof lands wherever you have control** — this is what makes ZONING adoptable
by organizations that cannot modify their system of record:

| You control… | Single-use enforcement |
|---|---|
| the datastore | a `UNIQUE(proof_id)` constraint — the database refuses the second write |
| only the service in front of a vendor/legacy system | that service consumes the proof once, atomically, then performs the mutation |
| only the edge | gateway-level enforcement + monitor mode — eliminates stolen-session mutation |

The full protocol is specified in [`SPEC.md`](SPEC.md).

---

## Reference Implementation

A runnable, tested implementation of the protocol lives in
[`python/`](python/) — the complete flow plus demonstrations of replay,
payload-tampering, bypass, forgery, stolen-session, and revoked-device attacks
all being refused, with the security properties captured as tests.

```bash
cd python
pip install -r requirements.txt
python demo.py          # full flow + attack demonstrations
python -m pytest -q     # security-property tests
```

---

## Scope

ZONING is for **high-value, low-frequency mutations** — not reads, not
high-frequency traffic. It adds one platform-native confirmation (seconds of human
time) and negligible machine latency to the operations where a human's judgment is
the whole point; everything else is untouched.

## Design constraints (deliberate)

No custom client cryptography (platform keystores / WebAuthn do the signing), no
blockchain, no PKI hierarchy, no HSM requirement, and no modification of systems you
do not control.

---

*Authored by **Geoffrey T. Iloani**. See [`SPEC.md`](SPEC.md) §11.*
