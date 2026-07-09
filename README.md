# ecrecover-schnorr-verifier

This repository includes an experimental library for Schnorr signature verification using ec-recover precompile

## Foundry dependencies

Foundry dependencies under `lib/` are intentionally not committed.

- `bun run forge:deps` installs `forge-std` locally with `forge install --no-git`.
- `bun run forge:test` bootstraps Foundry dependencies, builds the Rust signer helper, and runs the Forge suite.

## Formal verification

The `certora/` directory contains a Certora Prover setup: an assembly-free reference
implementation, CVL rules (input-domain handling, no-revert, determinism, and equivalence
between the optimized assembly and the reference), and `bun run certora` to launch a run.
See [certora/README.md](certora/README.md) for the property list and scope notes. CI runs
the prover via `.github/workflows/certora.yml` when the `CERTORAKEY` secret is configured.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
