## x402 Decentralized Facilitator - Progress & Notes

This document tracks the implementation to decentralize the x402 facilitator by introducing a quorum aggregator and attestations.

### Current State

- Added a quorum-based facilitator that:
  - Calls peer nodes for attestations on `/attest` during verify
  - Applies k-of-n quorum on attested results
  - Selects a single deterministic peer to settle to avoid duplicate broadcasts
- Added `POST /attest` on peer nodes that:
  - Computes a request hash
  - Runs local verify
  - Returns an `Attestation` including optional signature and signer address if `EVM_PRIVATE_KEY` is set
- Aggregator returns peer attestations in a response header `X-Attestations` (base64-encoded JSON array) for `POST /verify`.

### How to Run Locally

1) Start 2-3 peers (local mode):

```
HOST=127.0.0.1 PORT=8081 NODE_ID=peer1 cargo run
HOST=127.0.0.1 PORT=8082 NODE_ID=peer2 cargo run
HOST=127.0.0.1 PORT=8083 NODE_ID=peer3 cargo run
```

Optional: configure real RPC and key (example Base Sepolia):

```
SIGNER_TYPE=private-key \
EVM_PRIVATE_KEY=0x... \
RPC_URL_BASE_SEPOLIA=https://sepolia.base.org \
HOST=127.0.0.1 PORT=8081 NODE_ID=peer1 cargo run
```

2) Start the aggregator:

```
QUORUM_PEERS=http://127.0.0.1:8081,http://127.0.0.1:8082,http://127.0.0.1:8083 \
QUORUM_K=2 HOST=127.0.0.1 PORT=8090 \
cargo run
```

3) Point your x402 client to `http://127.0.0.1:8090`.

### API Changes

- New endpoint on peers: `POST /attest`
  - Request: `VerifyRequest`
  - Response: `Attestation` with fields:
    - `nodeId`, `requestHash`, `verifyResponse`
    - optional `signer` (address) and `signature` (0x-prefixed 65-byte ECDSA)
- Aggregator-only behavior:
  - `POST /verify` response includes header `X-Attestations` containing base64-encoded JSON array of `Attestation` from peers.

### Deterministic Peer Selection (settle)

- A single peer is chosen per request to broadcast settlements:
  - `index = keccak256(serde_json(request))[0] % N`
  - Prevents duplicate tx broadcasts and “already known” errors.

### Implementation Notes

- Code:
  - `src/facilitator_quorum.rs` — quorum logic + deterministic settle
  - `src/handlers.rs` — local `/attest` handler
  - `src/main.rs` — aggregator-mode `/verify` override to add `X-Attestations`
  - `src/types.rs` — `Attestation` struct + `signing_hash()` helper
- Env:
  - `QUORUM_PEERS`, `QUORUM_K`, `NODE_ID`
  - Optional signing on peers via `SIGNER_TYPE=private-key` and `EVM_PRIVATE_KEY`

### Next Steps

- Verify attestation signatures in the aggregator (EIP-191 or EIP-712) and discard invalid ones
- Support ed25519 (Solana) signatures for Solana-only nodes
- Onchain registry for peer discovery, staking, and slashing
- Reward disbursement mechanism for attestations and settlements
- Optional threshold/aggregated signatures to compress attestations


