# Formal verification with Certora

This directory contains the Certora Prover setup for `SchnorrVerifierLib`.

## Layout

- `harness/SchnorrVerifierHarness.sol` — verification-only contract exposing the optimized
  library verifier (`verifyOptimized`) next to an assembly-free reference implementation
  (`verifyReference`) of the same ecSchnorr\* construction.
- `specs/SchnorrVerifier.spec` — CVL rules.
- `confs/SchnorrVerifier.conf` — CI profile: the machine-provable rules.
- `confs/SchnorrVerifier-full.conf` — all rules, including the solver-limited ones.

## Properties and status

Status as of certora-cli 8.16.2 (prover reports:
[full run](https://prover.certora.com/output/8297013/870afaa6a4a144ab86af8f98f5743b10?anonymousKey=56067313ef772c0e57ceeb468419d25e462c4941),
[heavy-rules retry](https://prover.certora.com/output/8297013/351400f5bfd14a17b22ed4241885f69f?anonymousKey=bcd380153ca56dbf3a88bb92421820873e336199)):

| Rule                                       | Property                                                                      | Status    |
| ------------------------------------------ | ----------------------------------------------------------------------------- | --------- |
| `rejectsPublicKeyXOutsideScalarField`      | `publicKeyX ∉ [1, n-1]` ⇒ `false`                                             | ✅ proved |
| `rejectsSignatureScalarOutsideScalarField` | `signatureScalar ∉ [1, n-1]` ⇒ `false`                                        | ✅ proved |
| `rejectsNonceXOutsideBaseField`            | `nonceX ∉ [1, p-1]` ⇒ `false`                                                 | ✅ proved |
| `rejectsInvalidParity`                     | `publicKeyYParity > 1` ⇒ `false`                                              | ✅ proved |
| `acceptImpliesWellFormedInput`             | acceptance implies every input is inside its documented domain                | ✅ proved |
| `verifyNeverReverts`                       | `verify` never reverts on any input; the boolean is the only failure channel  | ⏱ timeout |
| `verifyIsDeterministic`                    | identical inputs yield identical results                                      | ⏱ timeout |
| `matchesReferenceImplementation`           | the optimized assembly agrees with the reference implementation on all inputs | ⏱ timeout |

The three timeout rules require the SMT solver to reason through byte-level memory
encodings combined with chains of nonlinear 256-bit modular arithmetic (`mulmod` over the
secp256k1 primes), which exceeds current solver capabilities even with a 1-hour per-query
budget (`SchnorrVerifier-full.conf`). They are excluded from the CI profile and remain
covered empirically by the differential fuzz suite
(`foundry-test/SchnorrVerifierReference.t.sol`, 10k runs of optimized-vs-reference on
arbitrary inputs plus honest-signature acceptance). Rule-level vacuity checks
(`rule_sanity`) are disabled for the same reason — synthesizing a non-vacuity witness
walks the same nonlinear paths; non-vacuity of the domain rules is evidenced by the fuzz
suite exercising every rejection branch.

## Scope

The prover models cryptographic primitives (`ecrecover`, SHA-256, keccak256, modexp) as
uninterpreted/summarized functions. These rules therefore verify the Solidity and assembly
plumbing of the verifier — input-domain handling, non-reverting behavior, memory/scratch-space
correctness via reference equivalence — **not** the cryptographic soundness of the ecSchnorr\*
construction itself, which is established by the accompanying paper.

## Running

```sh
export CERTORAKEY=<your key>
bun run certora                                            # CI profile (provable rules)
certoraRun certora/confs/SchnorrVerifier-full.conf         # all rules, expect timeouts
```

To attack a single solver-limited rule (as Certora support suggests for unfinished rules):

```sh
certoraRun certora/confs/SchnorrVerifier-full.conf --rule matchesReferenceImplementation
```

CI runs the same configuration via `.github/workflows/certora.yml`. To keep prover time
proportional to risk, the job first checks whether anything in the verification cone
changed (`certora/`, `contracts/libs/crypto/`, or the workflow itself):

- **Relevant changes** — the prover runs; the report URL is published to the job summary
  and uploaded as the `certora-report` artifact.
- **No relevant changes** — the prover is skipped and the job summary links the report of
  the most recent successful run instead (fetched from its `certora-report` artifact; GitHub
  retains artifacts for 90 days by default).

The prover step itself requires the `CERTORAKEY` repository secret and skips with a
warning when it is not configured.
