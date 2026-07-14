# Ecrecover Schnorr Verifier

An experimental, highly optimized BIP-340-compatible library for Schnorr signature verification using sha256 
and `ecrecover` precompile.

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

## BIP-340 compatibility

The verifier checks the BIP-340 equation `[s]G - [e]P = R` with the standard
tagged challenge hash. It agrees with BIP-340 exactly, up to the following:

- **Messages are exactly 32 bytes.** Variable-length messages, allowed by the
  current spec, are not representable in the `bytes32` ABI.
- **Pass `publicKeyYParity = 0`.** BIP-340 keys implicitly select the even-Y
  point; parity `1` verifies against the odd-Y point, outside BIP-340.
- **`publicKeyX` must be less than `n`.** It is routed through the ECDSA `r`
  slot, so valid BIP-340 keys with x-coordinate in `[n, p)` — a `~2^-128`
  fraction — are rejected.
- **Point comparison is by address.** Points are compared via their 160-bit
  `keccak256` address rather than exact coordinates, so the accepting direction
  rests on collision resistance.
- **Negligible edge cases are rejected**: `s = 0`, challenge `e = 0`, and a
  nonce point whose address is zero.

Note regarding the EIP-2 low-`s` rule: it constrains transaction signatures, 
not the `ecrecover` precompile, so no low-`s` nonce grinding is required.

## Tests

Hardhat: official BIP-340 vectors #1 and #3, range, parity, and zero-message
checks. Foundry: 10,000-run fuzz and differential tests against `secp256k1-zkp`
signatures. The upstream
[test-vector CSV](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv)
is not imported wholesale; its variable-length-message vectors cannot be
expressed in this ABI.

## Formal verification

Certora proves the optimized assembly equivalent to an assembly-free reference
implementation, covering input domains and plumbing — not the cryptographic
soundness of the construction, which is the subject of the paper. See
[certora/README.md](certora/README.md) for the property list, assumptions, and
scope notes.

## License

This project is licensed under the MIT License.
