# Ecrecover Schnorr Verifier

An experimental highly-optimized library for Schnorr signature verification using sha256 and ec-recover precompiles.

Gas usage: `7541`.

## Tests

Full BIP340 unit tests + fuzz tests coverage.

## Formal verification

The verifier implementation is formally verified via Certora against its non-optimized counterpart. See [certora/README.md](certora/README.md) for the property list and scope notes.

## License

This project is licensed under the MIT License.
