# Ecrecover Schnorr Verifier

An experimental, highly optimized BIP-340-compatible library for Schnorr signature verification using sha256 and ecrecover precompiles.

Gas usage: `6567`.

## Tests

Full BIP-340 unit tests + fuzz tests coverage.

## Formal verification

The verifier implementation is formally verified via Certora against its non-optimized counterpart. See [certora/README.md](certora/README.md) for the property list and scope notes.

## License

This project is licensed under the MIT License.
