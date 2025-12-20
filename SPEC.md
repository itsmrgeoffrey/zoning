# ZONING Specification v1.0
A Three-Zone Cryptographic Protocol for Transaction Authorization

## Status of This Document
This document defines ZONING v1.0, a transaction authorization protocol.
This specification is informational and intended for architectural review,
security analysis, and controlled implementation.

---

## 1. Introduction

ZONING is a protocol that enforces cryptographic proof of:
- identity (Zone 1),
- transaction integrity (Zone 2),
- and bank authorization (Zone 3)

before a financial transaction is executed.

ZONING is designed to address systemic weaknesses in session-based
transaction authorization models, where authentication is implicitly
treated as proof of intent.

---

## 2. Terminology

The following terms are used throughout this specification:

- **Client Device**: A user-controlled device capable of secure key storage.
- **Device Keypair**: A cryptographic keypair generated and stored on the client device.
- **Zone 1 Assertion (Z1A)**: A backend-issued reference binding a device public key to a user.
- **Canonical Payload**: A deterministic representation of a transaction payload.
- **txhash**: A deterministic cryptographic hash of the canonical payload and context.
- **Nonce**: A one-time value used to prevent replay.
- **FAT (Final Authorization Token)**: A bank-signed authorization required for execution.
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

A transaction MUST NOT be executed unless all three zones complete
successfully.

---

## 5. Zone 1 — Identity & Device Trust

### 5.1 Purpose
Zone 1 establishes cryptographic device identity.

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

---

## 6. Zone 2 — Transaction Integrity

### 6.1 Purpose
Zone 2 proves what exact transaction the user approved.

### 6.2 Inputs
- Transaction payload
- Zone 1 Assertion reference
- Device identifier
- Nonce

### 6.3 Process
1. The client MUST canonicalize the transaction payload deterministically.
2. The client MUST compute a txhash using:
   - canonical payload
   - device identifier
   - nonce
   - Zone 1 Assertion reference
3. The client MUST sign the txhash using the device private key.
4. The client MUST submit:
   - payload
   - nonce
   - txhash
   - device signature
   - Zone 1 Assertion reference

### 6.4 Backend Verification
The backend MUST:
- recompute the canonical payload
- recompute the txhash
- verify txhash equality
- verify the device signature
- reject reused nonces

### 6.5 Outputs
- Verified txhash
- Verified device signature

### 6.6 Guarantees
Zone 2 guarantees that the payload cannot be modified or replayed
without detection.

---

## 7. Zone 3 — Final Authorization

### 7.1 Purpose
Zone 3 enforces explicit bank authorization.

### 7.2 Inputs
- Verified Zone 1 Assertion
- Verified txhash
- Transaction reference

### 7.3 Process
1. The backend MUST verify Zone 1 and Zone 2 outputs.
2. Business, risk, and policy checks MUST be applied.
3. If approved, the bank MUST generate a Final Authorization Token (FAT).
4. The FAT MUST be cryptographically signed by the bank.
5. The FAT MUST bind to:
   - transaction reference
   - txhash
   - Zone 1 Assertion reference
   - issuance time
   - expiration time

### 7.4 Outputs
- Final Authorization Token (FAT)

### 7.5 Guarantees
Zone 3 guarantees that no transaction executes without explicit,
cryptographically provable bank approval.

---

## 8. Execution Rules

- An execution system MUST validate the FAT before execution.
- A transaction MUST NOT execute without a valid, unexpired FAT.
- A FAT MUST be bound to a single txhash.
- A FAT MUST NOT be reusable across transactions.

---

## 9. Security Guarantees

ZONING provides the following guarantees:

- Device-bound authorization
- Deterministic payload integrity
- Replay resistance
- Explicit bank consent
- Cryptographic auditability

---

## 10. Non-Goals

ZONING does not attempt to:
- replace authentication mechanisms
- define user interfaces
- replace fraud detection systems
- modify ledger implementations

ZONING complements existing systems.

---

## 11. Versioning

This document defines **ZONING v1.0**.

Future revisions MUST maintain backward compatibility or increment
the major version.

---

## 12. Authorship

ZONING is an original protocol authored by **Geoffrey T. Iloani**.

Public publication establishes authorship and version history.


ZONING divides transaction processing into three mandatory zones.

