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
