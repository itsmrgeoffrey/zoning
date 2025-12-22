# ZONING Specification v1.0
A Three-Zone Cryptographic Protocol for Transaction Authorization

## Status of This Document
This document defines ZONING v1.0, a transaction authorization protocol.
This specification is informational and intended for architectural review,
security analysis, and controlled implementation.

---

## 1. Introduction

ZONING is a protocol that enforces cryptographic proof of:
- identity and access (Zone 1),
- single-use transaction attempt confirmation (Zone 2),
- and controlled execution (Zone 3)

before a financial transaction is executed.

ZONING is designed to address systemic weaknesses in session-based
transaction authorization models, where authentication is implicitly
treated as proof of transactional authority.

---

## 2. Terminology

The following terms are used throughout this specification:

- **Client Device**: A user-controlled device capable of secure key storage.
- **Device Keypair**: A cryptographic keypair generated and stored on the client device.
- **Zone 1 Assertion (Z1A)**: A backend-issued reference binding a device public key to a user.
- **Canonical Payload**: A deterministic representation of a transaction payload.
- **txHash**: A deterministic cryptographic hash of the canonical payload and context.
- **Nonce / Challenge**: A one-time value used to prevent replay.
- **Attempt Receipt**: A single-use cryptographic proof that a logged-in human completed
  the final confirmation step for an exact transaction.
- **Execution System**: The system that performs the actual debit/credit.

---

## 3. Threat Model

ZONING assumes the following threats exist:

- Session tokens may be replayed or stolen
- Backend services may be misused or compromised
- API consumers may attempt unauthorized debits
- Payloads may be altered after user interaction
- Requests may be replayed outside their original context

ZONING does **not** assume:
- a trusted internal network
- honest intermediary services
- infallible authentication sessions

---

## 4. Protocol Overview

A transaction MUST NOT be executed unless all required zones complete
successfully.

Authentication alone MUST NOT be treated as transactional authority.

---

## 5. Zone 1 — Identity & Access

### 5.1 Purpose
Zone 1 establishes cryptographic device identity and authenticated access.

### 5.2 Inputs
- User identifier
- Device identifier
- Device public key

### 5.3 Process
1. The client device MUST generate a cryptographic keypair locally.
2. The private key MUST NOT leave the device.
3. The public key MUST be registered with the backend.
4. The backend MUST associate the public key with the user and device.
5. The backend MUST issue a Zone 1 Assertion reference (Z1A).

### 5.4 Outputs
- Zone 1 Assertion reference

### 5.5 Guarantees
Zone 1 guarantees that a future signature can be traced to a specific,
registered device.

Zone 1 grants access only and MUST NOT be treated as transactional authority.

---

## 6. Zone 2 — Transaction Attempt Confirmation

### 6.1 Purpose
Zone 2 proves that a logged-in human actively completed the final
transaction confirmation step for an exact transaction attempt.

### 6.2 Inputs
- Transaction payload
- Zone 1 Assertion reference
- Device identifier
- Nonce / backend-issued challenge

### 6.3 Process
1. The client MUST canonicalize the transaction payload deterministically.
2. The client MUST compute a txHash using:
   - canonical payload
   - device identifier
   - nonce / challenge
   - Zone 1 Assertion reference
3. The client MUST produce an Attempt Receipt by signing the txHash
   using the device private key.
4. The Attempt Receipt MUST only be produced immediately after a live,
   blocking user confirmation (e.g., PIN or biometric).

### 6.4 Backend Verification
The backend MUST:
- recompute the canonical payload
- recompute the txHash
- verify the Attempt Receipt signature
- verify freshness and single-use of the nonce / challenge
- reject reused Attempt Receipts

### 6.5 Outputs
- Verified Attempt Receipt
- Verified txHash

### 6.6 Guarantees
Zone 2 guarantees that:
- the exact transaction payload was confirmed
- the confirmation was performed by a logged-in human
- the confirmation is single-use and non-replayable

---

## 7. Zone 3 — Execution

### 7.1 Purpose
Zone 3 executes a transaction only after successful verification and
consumption of a valid Zone 2 Attempt Receipt.

### 7.2 Execution Rules
- A transaction MUST NOT execute without a valid, unused Attempt Receipt.
- An Attempt Receipt MUST be bound to a single txHash.
- An Attempt Receipt MUST be consumed exactly once prior to execution.
- Reuse of an Attempt Receipt MUST be rejected.

---

## 8. Security Guarantees

ZONING provides the following guarantees:

- Device-bound access
- Deterministic payload integrity
- Single-use attempt confirmation
- Replay resistance
- Cryptographic auditability

---

## 9. Non-Goals

ZONING does not attempt to:
- replace authentication mechanisms
- define user interfaces
- replace fraud detection systems
- modify ledger implementations

ZONING complements existing systems.

---

## 10. Versioning

This document defines **ZONING v1.0**.

Future revisions MUST maintain backward compatibility or increment
the major version.

---

## 11. Authorship

ZONING is an original protocol authored by **Geoffrey T. Iloani**.

Public publication establishes authorship and version history.
