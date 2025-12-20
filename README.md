# zoning
A 3-Zone Cryptographic Framework for Transaction Authorization
## Overview

ZONING is a transaction authorization framework that enforces **cryptographic proof**
of identity, payload integrity, and bank authorization **before a transaction is executed**.

Most financial systems today assume that a valid session (JWT, OAuth, API key)
is sufficient proof of user intent. ZONING rejects that assumption.

ZONING introduces a three-zone model where each zone produces a verifiable artifact
required by the next zone. A transaction cannot execute unless **all three zones succeed**.

---

## The Problem

Current banking and fintech architectures rely on session-based trust:

- User authenticates
- Session token is issued
- Any request with that token is treated as intentional

This model fails to cryptographically guarantee:
- which device initiated a transaction
- what exact payload the user approved
- whether the bank explicitly authorized that payload

This leads to:
- replay attacks
- payload tampering
- device impersonation
- partner-initiated unauthorized debits
- internal service abuse

ZONING addresses this gap.

---

## ZONING Architecture

