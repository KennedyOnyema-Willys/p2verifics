# p2verifics

A proof-of-concept Privacy-Preserving Verifiable Credential System using [BBS signatures](https://github.com/digitalbazaar/bbs-signatures) for selective disclosure.

## Overview

This project demonstrates a three-party credential flow:

1. **Issuer** (`issuer.js`) — generates a key pair, signs a credential containing multiple claims, and writes `credential.json`.
2. **Holder** (`holder.js`) — reads `credential.json`, selectively discloses a subset of claims by deriving a zero-knowledge proof, and writes `presentation.json`.
3. **Verifier** (`verifier.js`) — reads `presentation.json` and cryptographically verifies the proof without seeing the undisclosed claims.

## Requirements

- Node.js ≥ 18

## Setup

```bash
npm install
```

## Usage

Run each step in order:

```bash
# Step 1 – Issue a credential
npm run issue

# Step 2 – Create a selective-disclosure presentation
npm run hold

# Step 3 – Verify the presentation
npm run verify
```

`credential.json` and `presentation.json` are runtime artifacts and are excluded from version control.

