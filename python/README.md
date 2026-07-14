# ZONING — Python Reference Implementation

A runnable, tested reference implementation of the ZONING protocol defined in
[`../SPEC.md`](../SPEC.md). It demonstrates the full authorization flow and
refuses six classes of attack, with the security properties pinned down as
tests.

## Mapping to the specification

| SPEC.md | This implementation |
|---|---|
| **Zone 1 — Identity & Access** | device enrollment: a P-256 keypair in the platform keystore; the public key is registered over an authenticated session (`Verifier.enroll_device`) |
| **Zone 2 — Transaction Attempt Confirmation** | server-issued challenge → on-device signature → verifier mints a single-use, payload-bound **Mutation Proof** (`Verifier.verify_and_mint`) |
| **Zone 3 — Execution** | the *innermost gate the operator controls* consumes the proof exactly once, then executes: a `UNIQUE(proof_id)` datastore constraint, or the atomic `ConsumedRegistry` when the datastore cannot be touched |

The Attempt Receipt of the spec is realized here as a compact, verifier-signed
proof that every hop on the write path verifies **statelessly** (signature +
payload-hash comparison) — so the interior of the system no longer implicitly
trusts the interior.

## Run it

```bash
pip install -r requirements.txt
python demo.py          # full flow + six attack demonstrations
python -m pytest -q     # 16 security-property tests
```

## Files

- `zoning.py` — the complete implementation (~300 lines; stdlib + `cryptography`)
- `demo.py` — end-to-end flow; demonstrates replay, payload tampering, no-proof
  bypass, forged proof, stolen-session, and revoked-device all being refused
- `test_zoning.py` — the security properties as executable tests

## Design constraints (deliberate)

No custom client cryptography (platform keystores / WebAuthn do the signing),
no blockchain, no PKI hierarchy, no HSM requirement, and — per SPEC §9 — **no
modification of ledger or execution systems you do not control**. Single-use is
enforced at the innermost gate available: a database `UNIQUE` constraint where
the datastore is yours, an atomic in-service registry where it is not.

## Scope

ZONING is intended for **high-value, low-frequency mutations** (transfers,
beneficiary/payee changes, role grants, config changes), not for reads or
high-frequency traffic. Applying it beyond that scope trades user friction for
no benefit.

Author: **Geoffrey T. Iloani** — see [`../SPEC.md`](../SPEC.md) §11.
