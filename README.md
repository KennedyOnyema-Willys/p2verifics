# p2verifics

Privacy-preserving verifiable credential demo using BBS signatures (`@digitalbazaar/bbs-signatures`).

This project simulates three roles:

- `issuer`: creates a signed credential for a holder.
- `holder`: selectively discloses requested fields and generates a proof.
- `verifier`: creates a request and verifies the holder's proof offline.

## What this demo proves

- A verifier can check that disclosed claims are signed by the issuer.
- The holder can reveal only policy-required fields (not the full credential).
- Verification includes proof validity and credential expiry check.

## Requirements

- Node.js 18+ (recommended)
- npm

## Install

```bash
npm install
```

## Quick Start (Interactive)

Run the single-runner menu:

```bash
npm start
```

You can run:

- `1) Issue ID`
- `2) Verifier creates request`
- `3) Holder responds`
- `4) Verifier verifies`
- `5) Full flow` (recommended for a clean demo)

## Direct CLI Usage

### Issue a credential

```bash
node issuer.js
```

Writes:

- `holder_store/credential.json`

### Create a verifier request

```bash
node verifier.js request 1A "E-Corp"
```

Writes:

- `request.json`

### Holder creates presentation (consent flow)

```bash
node holder.js
```

Writes:

- `presentation.json` (if consent = yes)

### Verify presentation

```bash
node verifier.js verify "E-Corp"
```

Writes:

- `verification_result.json`

## Request Codes

- `1A`: validate age over 18
- `1B`: validate age over 21
- `2A`: validate age and name

Policy definitions are in `utils.js` under `REQUEST_POLICIES`.

## Project Files

- `interactive.js`: menu runner for full workflow
- `issuer.js`: credential issuance and signing
- `holder.js`: selective disclosure + proof derivation
- `verifier.js`: request generation + proof verification
- `utils.js`: crypto helpers and policy definitions

Output artifacts:

- `holder_store/credential.json`
- `request.json`
- `presentation.json`
- `verification_result.json`

## Verification Result Fields

`verification_result.json` includes:

- `verifiedProof`: cryptographic proof verification result
- `notExpired`: whether disclosed `expiry` is in the future
- `valid`: `verifiedProof && notExpired`
- `disclosed`: disclosed key/value claims
- `computedAge`: only present when `dob` is disclosed (e.g., `2A`)

## Troubleshooting

- If verification fails, regenerate artifacts in order:
  1. issue
  2. request
  3. presentation
  4. verify
- Do not reuse old `presentation.json` with a new `request.json`.
- Use interactive option `7` to reset session files (`request/presentation/verification`) when testing repeatedly.

## Notes

- This is a local proof-of-concept, not production credential infrastructure.
- No network transport, revocation, or DID resolution is implemented.
