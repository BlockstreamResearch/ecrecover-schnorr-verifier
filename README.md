# Ecrecover Schnorr Verifier

An experimental, highly optimized BIP-340-compatible library for Schnorr signature verification using sha256
and `ecrecover` precompile.

Gas usage on official BIP-340 vector #3: `32681` for `verify` and `28689` for
`verifyWithNonceY`.

## BIP-340 compatibility

The verifier checks the BIP-340 equation `[s]G - [e]P = R` with the standard
tagged challenge hash. It agrees with BIP-340 algebraically, up to the following:

- **Messages are exactly 32 bytes.** Variable-length messages, allowed by the
  current spec, are not representable in the `bytes32` ABI.
- **Public keys are x-only.** `publicKeyX` selects the even-Y BIP-340 point.
- **`publicKeyX` must be less than `n`.** It is routed through the ECDSA `r`
  slot, so valid BIP-340 keys with x-coordinate in `[n, p)` — a `~2^-128`
  fraction — are rejected.
- **Point comparison is by address.** The verifier compares 160-bit Ethereum
  addresses rather than exact points, so security is conditional on the
  related-point address-collision (RPAC) assumption described in the paper.
- **Challenge `e = 0` and a zero recovered address are rejected.** The scalar
  `s` otherwise uses BIP-340's full range `[0, n)`.

`verifyWithNonceY` accepts an even nonce Y coordinate and validates its range,
parity, and curve equation before using the same verification path as `verify`.

For ChillDKG/FROST, the application must authorize the final x-only key after
all BIP445 tweaks and bind the tweak and signing context, exact 32-byte message
domain, freshness, and replay policy. These checks are outside this stateless
verifier.

Note regarding the EIP-2 low-`s` rule: it constrains transaction signatures,
not the `ecrecover` precompile, so no low-`s` nonce grinding is required.

## Tests

Hardhat: official BIP-340 vectors #1 and #3, range, zero-message, nonce-witness,
and gas checks. Foundry: 10,000-run fuzz and differential tests against
`secp256k1-zkp` signatures. The upstream
[test-vector CSV](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv)
is not imported wholesale; its variable-length-message vectors cannot be
expressed in this ABI.

## Formal verification

Certora proves the optimized assembly equivalent to an assembly-free reference
implementation, covering input domains and plumbing — not RPAC hardness or the
application-level integration requirements. See
[certora/README.md](certora/README.md) for the property list, assumptions, and
scope notes.

## License

This project is licensed under the MIT License.
