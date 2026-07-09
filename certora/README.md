# Formal verification with Certora

This directory contains the Certora Prover setup for `SchnorrVerifierLib`.

## Layout

- `harness/SchnorrVerifierHarness.sol` — verification-only contract exposing the optimized
  library verifier (`verifyOptimized`) next to an assembly-free reference implementation
  (`verifyReference`) of the same ecSchnorr\* construction.
- `specs/SchnorrVerifier.spec` — monolithic CVL rules (no summaries).
- `specs/SchnorrVerifierModular.spec` — the no-revert, determinism and equivalence rules
  under paired deterministic summaries of the crypto helpers (see below).
- `confs/SchnorrVerifier.conf` — CI profile of the monolithic spec: the domain rules.
- `confs/SchnorrVerifier-modular.conf` — CI profile of the modular spec.
- `confs/SchnorrVerifier-full.conf` — the monolithic spec including the three rules that
  are infeasible without summaries; retained as documentation of that limit.

## Properties and status

Status as of certora-cli 8.16.2 (prover reports:
[domain rules](https://prover.certora.com/output/8297013/b974fcabecfd40fcb929f601b168aa5c),
[modular rules](https://prover.certora.com/output/8297013/4fa19ad4e74b4d1f8f6e486d8bf5643b),
[monolithic attempt](https://prover.certora.com/output/8297013/351400f5bfd14a17b22ed4241885f69f?anonymousKey=bcd380153ca56dbf3a88bb92421820873e336199)):

| Rule                                       | Property                                                                     | Status              |
| ------------------------------------------ | ---------------------------------------------------------------------------- | ------------------- |
| `rejectsPublicKeyXOutsideScalarField`      | `publicKeyX ∉ [1, n-1]` ⇒ `false`                                            | ✅ proved           |
| `rejectsSignatureScalarOutsideScalarField` | `signatureScalar ∉ [1, n-1]` ⇒ `false`                                       | ✅ proved           |
| `rejectsNonceXOutsideBaseField`            | `nonceX ∉ [1, p-1]` ⇒ `false`                                                | ✅ proved           |
| `rejectsInvalidParity`                     | `publicKeyYParity > 1` ⇒ `false`                                             | ✅ proved           |
| `acceptImpliesWellFormedInput`             | acceptance implies every input is inside its documented domain               | ✅ proved           |
| `verifyNeverReverts`                       | `verify` never reverts on any input; the boolean is the only failure channel | ✅ proved (modular) |
| `verifyIsDeterministic`                    | identical inputs yield identical results                                     | ✅ proved (modular) |
| `matchesReferenceImplementation`           | optimized assembly and reference implementation agree on all inputs          | ✅ proved (modular) |

## The modular decomposition

The last three rules are **unprovable in their monolithic form** — and not merely because
of solver capacity. The Prover models unresolved `STATICCALL`s with `NONDET` summaries,
so the raw assembly calls to the SHA-256 (`0x02`) and modexp (`0x05`) precompiles return
a fresh nondeterministic value on every invocation. Under that model two identical hash
invocations may differ, which directly falsifies determinism and reference equivalence;
the surrounding chains of nonlinear 256-bit `mulmod` additionally push the SMT queries
past a 1-hour per-query budget (`SchnorrVerifier-full.conf`, kept for reproducing this).

`SchnorrVerifierModular.spec` restores provability by summarizing each library helper
together with its reference counterpart using the _same_ deterministic ghost-backed CVL
function, removing the precompile calls from the verified cone. What is then **proved**
(in seconds) is the entire orchestration of `verify`: input validation, short-circuit
ordering, challenge negation, argument wiring into the recovery call, and the final
address comparison — for _every possible behavior_ of the crypto primitives.

What is **assumed** by the pairing (each axiom covered by the differential fuzz suite in
`foundry-test/SchnorrVerifierReference.t.sol`, 10k runs):

1. `_liftXToEvenY` ≡ `_liftXToEvenYReference`, `_challengeBIP340` ≡ `_challengeReference`,
   `_pointAddress` ≡ `_pointAddressReference`, `_recoverAddress` ≡ `_recoverReference` —
   i.e. the leaf crypto helpers compute the same functions.
2. Challenge scalars are reduced mod n (true by construction on both sides; without this
   the unconstrained ghost admits `n - challengeScalar` underflowing — a model artifact).
3. Helper bodies never revert (they contain no revert paths; assembly staticcalls signal
   failure through their boolean result).

Rule-level vacuity checks (`rule_sanity`) are disabled: synthesizing a non-vacuity
witness walks the nonlinear paths described above; non-vacuity is evidenced by the fuzz
suite exercising every branch.

## Scope

The prover models cryptographic primitives (`ecrecover`, SHA-256, keccak256, modexp) as
uninterpreted/summarized functions. These rules therefore verify the Solidity and assembly
plumbing of the verifier — input-domain handling, non-reverting behavior, memory/scratch-space
correctness via reference equivalence — **not** the cryptographic soundness of the ecSchnorr\*
construction itself, which is established by the accompanying paper.

## Running

```sh
export CERTORAKEY=<your key>
bun run certora                                             # domain rules (monolithic spec)
certoraRun certora/confs/SchnorrVerifier-modular.conf       # no-revert, determinism, equivalence
certoraRun certora/confs/SchnorrVerifier-full.conf          # monolithic heavy rules, expect timeouts
```

CI runs the two CI profiles via `.github/workflows/certora.yml`. To keep prover time
proportional to risk, the job first checks whether anything in the verification cone
changed (`certora/`, `contracts/libs/crypto/`, or the workflow itself):

- **Relevant changes** — the prover runs; the report URL is published to the job summary
  and uploaded as the `certora-report` artifact.
- **No relevant changes** — the prover is skipped and the job summary links the report of
  the most recent successful run instead (fetched from its `certora-report` artifact; GitHub
  retains artifacts for 90 days by default).

The prover step itself requires the `CERTORAKEY` repository secret and skips with a
warning when it is not configured.
