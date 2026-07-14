/*
 * Modular Certora specification for SchnorrVerifierLib.
 *
 * Why this spec exists: the Prover models unresolved STATICCALLs with NONDET summaries,
 * so the library's raw assembly calls to the SHA-256 (0x02) and modexp (0x05) precompiles
 * return a fresh nondeterministic value on every invocation. Under that model the
 * determinism and reference-equivalence rules of `SchnorrVerifier.spec` are unprovable in
 * principle (two identical hash calls may differ), and the no-revert rule drowns in the
 * nonlinear path conditions surrounding those calls.
 *
 * This spec restores provability by modularization: each cryptographic helper of the
 * library is summarized together with its counterpart in the reference implementation
 * using the SAME deterministic ghost-backed CVL function. What remains in the verified
 * cone is the orchestration logic of `verify` — input validation, short-circuit ordering,
 * challenge negation, argument wiring into the recovery call, and the final address
 * comparison.
 *
 * Explicit axioms introduced by the pairing (each covered empirically by the differential
 * fuzz suite in `foundry-test/SchnorrVerifierReference.t.sol`):
 * - SchnorrVerifierLib._liftXToEvenY        ≡ SchnorrVerifierHarness._liftXToEvenYReference
 * - SchnorrVerifierLib._challengeBIP340     ≡ SchnorrVerifierHarness._challengeReference
 * - SchnorrVerifierLib._pointAddress        ≡ SchnorrVerifierHarness._pointAddressReference
 * - SchnorrVerifierLib._recoverAddress      ≡ SchnorrVerifierHarness._recoverReference
 * - helper bodies themselves never revert (they contain no revert paths; assembly
 *   staticcalls signal failure through their boolean result).
 */

methods {
    function verifyOptimized(
        uint256, uint8, uint256, bytes32, uint256
    ) external returns (bool) envfree;

    function verifyReference(
        uint256, uint8, uint256, bytes32, uint256
    ) external returns (bool) envfree;

    function verifyWithNonceYOptimized(
        uint256, uint8, uint256, bytes32, uint256, uint256
    ) external returns (bool) envfree;

    function verifyWithNonceYReference(
        uint256, uint8, uint256, bytes32, uint256, uint256
    ) external returns (bool) envfree;

    function SchnorrVerifierLib._liftXToEvenY(
        uint256 pointX_
    ) internal returns (bool, uint256) => liftSummary(pointX_);

    function SchnorrVerifierHarness._liftXToEvenYReference(
        uint256 pointX_
    ) internal returns (bool, uint256) => liftSummary(pointX_);

    function SchnorrVerifierLib._challengeBIP340(
        uint256 nonceX_,
        uint256 publicKeyX_,
        bytes32 messageHash_
    ) internal returns (bool, uint256) => challengeSummary(nonceX_, publicKeyX_, messageHash_);

    function SchnorrVerifierHarness._challengeReference(
        uint256 nonceX_,
        uint256 publicKeyX_,
        bytes32 messageHash_
    ) internal returns (bool, uint256) => challengeSummary(nonceX_, publicKeyX_, messageHash_);

    function SchnorrVerifierLib._pointAddress(
        uint256 pointX_,
        uint256 pointY_
    ) internal returns (address) => pointAddressSummary(pointX_, pointY_);

    function SchnorrVerifierHarness._pointAddressReference(
        uint256 pointX_,
        uint256 pointY_
    ) internal returns (address) => pointAddressSummary(pointX_, pointY_);

    function SchnorrVerifierLib._recoverAddress(
        bytes32 messageForRecover_,
        uint256 recoveryId_,
        bytes32 signatureR_,
        bytes32 signatureS_
    ) internal returns (address) =>
        recoverSummary(messageForRecover_, recoveryId_, signatureR_, signatureS_);

    function SchnorrVerifierHarness._recoverReference(
        bytes32 messageForRecover_,
        uint256 recoveryId_,
        bytes32 signatureR_,
        bytes32 signatureS_
    ) internal returns (address) =>
        recoverSummary(messageForRecover_, recoveryId_, signatureR_, signatureS_);
}

/* Deterministic uninterpreted models: unconstrained values, but the same arguments
 * always produce the same result — within a rule and across both implementations. */

ghost mapping(uint256 => bool) liftValidGhost;
ghost mapping(uint256 => uint256) liftYGhost;

function liftSummary(uint256 pointX) returns (bool, uint256) {
    return (liftValidGhost[pointX], liftYGhost[pointX]);
}

definition SECP256K1_SCALAR_ORDER() returns uint256 =
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
definition SECP256K1_FIELD_PRIME() returns uint256 =
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

ghost mapping(uint256 => mapping(uint256 => mapping(bytes32 => bool))) challengeOkGhost;
ghost mapping(uint256 => mapping(uint256 => mapping(bytes32 => uint256))) challengeScalarGhost;

function challengeSummary(
    uint256 nonceX,
    uint256 publicKeyX,
    bytes32 messageHash
) returns (bool, uint256) {
    uint256 challengeScalar = challengeScalarGhost[nonceX][publicKeyX][messageHash];

    // True by construction: both implementations reduce the SHA-256 digest mod n
    // (`mod(mload(0x00), n)` in the library, `% n` in the reference) before returning.
    // Without it the unconstrained ghost admits `challengeScalar >= n`, making the
    // caller's `n - challengeScalar` negation underflow — a model artifact, not a
    // reachable behavior.
    require challengeScalar < SECP256K1_SCALAR_ORDER(),
        "BIP340 challenge scalars are reduced mod n by construction";

    return (challengeOkGhost[nonceX][publicKeyX][messageHash], challengeScalar);
}

ghost mapping(uint256 => mapping(uint256 => address)) pointAddressGhost;

function pointAddressSummary(uint256 pointX, uint256 pointY) returns (address) {
    return pointAddressGhost[pointX][pointY];
}

ghost mapping(bytes32 => mapping(uint256 => mapping(bytes32 => mapping(bytes32 => address)))) recoverGhost;

function recoverSummary(
    bytes32 messageForRecover,
    uint256 recoveryId,
    bytes32 signatureR,
    bytes32 signatureS
) returns (address) {
    return recoverGhost[messageForRecover][recoveryId][signatureR][signatureS];
}

/// verify() must never revert, no matter the input. Modulo the summarized helper bodies
/// (which contain no revert paths), the boolean result is the only failure channel.
rule verifyNeverReverts(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    verifyOptimized@withrevert(publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX);

    assert !lastReverted;
}

/// With the crypto primitives modeled deterministically, identical inputs yield
/// identical results.
rule verifyIsDeterministic(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    bool firstResult = verifyOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX
    );
    bool secondResult = verifyOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX
    );

    assert firstResult == secondResult;
}

/// The orchestration of the optimized verifier agrees with the reference implementation
/// on every input, for every possible behavior of the (summarized) crypto primitives:
/// same range checks, same short-circuits, same challenge negation, same argument wiring
/// into the recovery call, same final comparison.
rule matchesReferenceImplementation(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    bool optimizedResult = verifyOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX
    );
    bool referenceResult = verifyReference(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX
    );

    assert optimizedResult == referenceResult;
}

/// verifyWithNonceY() must never revert, no matter the input. The witness checks are
/// pure field arithmetic (`mulmod`/`addmod` cannot revert), so the boolean result stays
/// the only failure channel.
rule verifyWithNonceYNeverReverts(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX,
    uint256 nonceY
) {
    verifyWithNonceYOptimized@withrevert(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX, nonceY
    );

    assert !lastReverted;
}

/// With the crypto primitives modeled deterministically, identical inputs yield
/// identical results on the witness path.
rule verifyWithNonceYIsDeterministic(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX,
    uint256 nonceY
) {
    bool firstResult = verifyWithNonceYOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX, nonceY
    );
    bool secondResult = verifyWithNonceYOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX, nonceY
    );

    assert firstResult == secondResult;
}

/// The orchestration of the optimized witness-based verifier agrees with its
/// assembly-free reference implementation on every input, for every possible behavior
/// of the (summarized) crypto primitives. The witness validation itself is concrete
/// field arithmetic on both sides and stays inside the verified cone.
rule witnessMatchesReferenceImplementation(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX,
    uint256 nonceY
) {
    bool optimizedResult = verifyWithNonceYOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX, nonceY
    );
    bool referenceResult = verifyWithNonceYReference(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX, nonceY
    );

    assert optimizedResult == referenceResult;
}

/// Cross-path equivalence: whenever the (summarized) lift reports `nonceX` on-curve and
/// its output is a well-formed even-y witness — which the real lift guarantees by
/// construction — verifying with that witness is indistinguishable from the self-lifting
/// verifier. This is the formal counterpart of the differential fuzz rule
/// `testFuzzWitnessPathMatchesModexpPath`.
rule witnessPathAgreesWithModexpPathOnLiftedWitness(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    require liftValidGhost[nonceX],
        "the modexp path only proceeds when the lift succeeds";

    uint256 liftedNonceY = liftYGhost[nonceX];

    // True by construction of `_liftXToEvenY` on both sides: the returned y-coordinate
    // is a canonical even field element satisfying the curve equation. Without these the
    // unconstrained ghost admits lift outputs the concrete witness checks reject — a
    // model artifact, not a reachable behavior.
    require liftedNonceY < SECP256K1_FIELD_PRIME(),
        "lift outputs are reduced mod p by construction";
    require liftedNonceY % 2 == 0,
        "lift outputs are canonicalized to the even branch by construction";
    require (liftedNonceY * liftedNonceY) % SECP256K1_FIELD_PRIME()
        == (nonceX * nonceX * nonceX + 7) % SECP256K1_FIELD_PRIME(),
        "lift outputs satisfy the curve equation by construction";

    bool modexpPathResult = verifyOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX
    );
    bool witnessPathResult = verifyWithNonceYOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX, liftedNonceY
    );

    assert witnessPathResult == modexpPathResult;
}
