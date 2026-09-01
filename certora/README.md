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

Status as of certora-cli 8.19.1: the current parity-free, BIP340-scalar-range
[domain](https://prover.certora.com/output/8297013/9f40681bc4694b7b87c027c65b0d75a9)
and [modular](https://prover.certora.com/output/8297013/52d8b06d907b4bd5a790fc5e8d1dcc5a)
profiles prove all 15 configured rules.

| Rule                                       | Property                                                            | Status              |
| ------------------------------------------ | ------------------------------------------------------------------- | ------------------- |
| `rejectsPublicKeyXOutsideScalarField`      | `publicKeyX ∉ [1, n-1]` ⇒ `false`                                   | ✅ proved           |
| `rejectsSignatureScalarOutsideScalarField` | `signatureScalar >= n` ⇒ `false`; zero is in range                  | ✅ proved           |
| `rejectsNonceXOutsideBaseField`            | `nonceX ∉ [1, p-1]` ⇒ `false`                                       | ✅ proved           |
| `acceptImpliesWellFormedInput`             | acceptance implies every input is inside its documented domain      | ✅ proved           |
| `verifyNeverReverts`                       | ABI-decodable typed inputs use only the boolean failure channel     | ✅ proved (modular) |
| `verifyIsDeterministic`                    | identical inputs yield identical results                            | ✅ proved (modular) |
| `matchesReferenceImplementation`           | optimized assembly and reference implementation agree on all inputs | ✅ proved (modular) |

| Rule                                    | Property                                                  | Status              |
| --------------------------------------- | --------------------------------------------------------- | ------------------- |
| `rejectsNonceYOutsideBaseField`         | witnesses outside the secp256k1 field are rejected        | ✅ proved           |
| `rejectsOddNonceY`                      | odd nonce witnesses are rejected                          | ✅ proved           |
| `witnessAcceptImpliesWellFormedInput`   | acceptance implies the documented witness input domains   | ✅ proved           |
| `verifyWithNonceYNeverReverts`          | ABI-decodable typed witness inputs never revert           | ✅ proved (modular) |
| `witnessMatchesReferenceImplementation` | optimized and reference witness paths agree on all inputs | ✅ proved (modular) |

| Rule                                    | Paper-edge policy                                          | Status              |
| --------------------------------------- | ---------------------------------------------------------- | ------------------- |
| `zeroSignatureScalarCanReachAcceptance` | `s = 0` is not rejected at the scalar-domain boundary      | ✅ proved (modular) |
| `rejectsZeroChallenge`                  | both paths reject a successfully computed `e = 0`          | ✅ proved (modular) |
| `rejectsZeroRecoveryResult`             | failed/zero recovery cannot pass, even if expected is zero | ✅ proved (modular) |

## The modular decomposition

The modular-only rules are **unprovable in their monolithic form** — and not merely because
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

What is **assumed** by the pairing (each helper-pair axiom covered by the differential fuzz
suite in `foundry-test/SchnorrVerifierReference.t.sol`, 10k runs):

1. `_liftXToEvenY` ≡ `_liftXToEvenYReference`, `_challengeBIP340` ≡ `_challengeReference`,
   `_pointAddress` ≡ `_pointAddressReference`, `_recoverAddress` ≡ `_recoverReference` —
   i.e. the leaf crypto helpers compute the same functions.
2. Challenge scalars are reduced mod n (true by construction on both sides; without this
   the unconstrained ghost admits `n - challengeScalar` underflowing — a model artifact).
3. Helper bodies never revert (they contain no revert paths; assembly staticcalls signal
   failure through their boolean result).

The three paper-edge rules additionally use deterministic ghost modes to force a matching
nonzero point/recovery address or a zero recovery result. They prove the surrounding
orchestration honors the `s = 0`, `e != 0`, and zero-recovery policies for those primitive
outcomes; they do not prove SHA-256, ECRECOVER, Keccak, or RPAC themselves.

Rule-level vacuity checks (`rule_sanity`) are disabled: synthesizing a non-vacuity
witness walks the nonlinear paths described above; non-vacuity is evidenced by the fuzz
suite exercising every branch.

## Scope

The prover models cryptographic primitives (`ecrecover`, SHA-256, keccak256, modexp) as
uninterpreted/summarized functions. These rules therefore verify the Solidity and assembly
plumbing of the verifier — input-domain handling, non-reverting behavior, memory/scratch-space
correctness via reference equivalence — **not** the cryptographic soundness of the ecSchnorr\*
construction itself. The accompanying paper gives a conditional reduction; it does not
establish unconditional equivalence or derive the hardness of RPAC.

## Security-assurance boundary

The production ABI exposes x-only public keys, and the production and reference verifiers
use the canonical even public-key branch with fixed recovery id `27`. Both reject `e = 0`
explicitly and accept `s = 0` at the scalar-domain boundary. Certora does not establish that
`publicKeyX` is the final effective x-only key after every BIP445 tweak. The integrating
application must authenticate every ordered tweak scalar and plain/x-only mode bit, authorize
the resulting final key, and bind that key plus the complete tweak and signing context, exact
32-byte message domain, freshness, and replay policy. Dynamic tweaks must be fixed before
nonce generation; secret nonces from an aborted late-tweak session must never be reused.

The verifier compares only 160-bit Ethereum addresses. Formal plumbing equivalence therefore
does not remove the related-point address-collision (RPAC) assumption. Ordinary collision
resistance gives only a conservative 80-bit generic bound; a 128-bit claim requires an
explicit assumption that RPAC itself has at least 128 bits of security.

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
