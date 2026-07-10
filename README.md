# Ecrecover Schnorr Verifier

An experimental, highly optimized BIP-340-compatible library for Schnorr signature verification using sha256 and ecrecover precompiles.

## Gas usage

Two entry points are provided:

- `verify` — reconstructs the nonce point y-coordinate on-chain via a modexp square root.
- `verifyWithNonceY` — takes the even y-coordinate as one extra word of calldata (computed
  off-chain by any secp256k1 library) and validates it with two field multiplications,
  skipping the modexp precompile entirely. Since EIP-7883 (Fusaka) repriced modexp, this
  is the cheaper path on mainnet.

Execution gas of the internal library call (BIP340 test vector #3, measured by
`foundry-test/SchnorrVerifierGas.t.sol`):

| EVM version                  | `verify` | `verifyWithNonceY` | saved |
| ---------------------------- | -------- | ------------------ | ----- |
| paris                        | `6605`   | `4713`             | 1892  |
| prague (pre-Fusaka mainnet)  | `6581`   | `4702`             | 1879  |
| osaka (mainnet since Fusaka) | `9280`   | `4702`             | 4578  |

The witness costs at most 512 gas of extra calldata (32 non-zero bytes), so the net
saving on post-Fusaka mainnet is ≈4000 gas per verification.

## Tests

Full BIP-340 unit tests + fuzz tests coverage.

## Formal verification

The verifier implementation is formally verified via Certora against its non-optimized counterpart. See [certora/README.md](certora/README.md) for the property list and scope notes.

## License

This project is licensed under the MIT License.
