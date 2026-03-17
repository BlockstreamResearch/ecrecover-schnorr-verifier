# ecrecover-schnorr-verifier

This repository includes an experimental library for Schnorr signature verification using ec-recover precompile

## Foundry dependencies

Foundry dependencies under `lib/` are intentionally not committed.

- `bun run forge:deps` installs `forge-std` locally with `forge install --no-git`.
- `bun run forge:test` bootstraps Foundry dependencies, builds the Rust signer helper, and runs the Forge suite.
