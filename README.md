# zoning
A 3-Zone Cryptographic Framework for Transaction Authorization

## Overview

ZONING is a transaction authorization framework that enforces **cryptographic proof**
of identity and **single-use transaction attempt confirmation** before a transaction
is executed.

Most financial systems today assume that a valid session (JWT, OAuth, API key)
is sufficient proof that a user intended a transaction. ZONING rejects that assumption.

ZONING introduces a three-zone model where **authentication grants access only**, and
each irreversible transaction requires a **fresh, verifiable proof that a logged-in
human actively completed the final confirmation step for that exact transaction**.

A transaction MUST NOT execute unless all required zones succeed.

---

## The Problem

Current banking and fintech architectures rely on session-based trust:

- User authenticates
- Session token is issued
- Any request with that token is treated as intentional

This model fails to cryptographically guarantee:
- which device initiated a transaction
- what exact payload the user approved
- whether the transaction was actively attempted at execution time

This leads to:
- session replay attacks
- payload tampering
- device impersonation
- partner-initiated unauthorized debits
- internal service abuse

ZONING addresses this gap by removing sessions as a source of transactional authority.

---

## ZONING Architecture

ZONING is organized into three zones. Authentication grants access only; each
irreversible transaction requires its own fresh, single-use proof.

- **Zone 1 — Identity & Access.** A device keypair is generated in the platform
  keystore and its public key registered to the user. Grants access, never
  transactional authority.
- **Zone 2 — Transaction Attempt Confirmation.** For each transaction the
  backend issues a challenge bound to the exact (canonical) payload; the device
  signs it only after a live, blocking user confirmation (biometric/PIN),
  producing a single-use Attempt Receipt.
- **Zone 3 — Execution.** The transaction executes only after a valid Attempt
  Receipt is verified and consumed exactly once — at the innermost execution
  gate the operator controls.

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
