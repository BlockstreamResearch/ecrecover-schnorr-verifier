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
        uint256, uint256, bytes32, uint256
    ) external returns (bool) envfree;

    function verifyReference(
        uint256, uint256, bytes32, uint256
    ) external returns (bool) envfree;

    function verifyWithNonceYOptimized(
        uint256, uint256, bytes32, uint256, uint256
    ) external returns (bool) envfree;

    function verifyWithNonceYReference(
        uint256, uint256, bytes32, uint256, uint256
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
definition GENERATOR_X() returns uint256 =
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
definition GENERATOR_EVEN_Y() returns uint256 =
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

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
ghost bool forceMatchingAddresses;
ghost address forcedMatchingAddress;

function pointAddressSummary(uint256 pointX, uint256 pointY) returns (address) {
    if (forceMatchingAddresses) {
        return forcedMatchingAddress;
    }
    return pointAddressGhost[pointX][pointY];
}

ghost mapping(bytes32 => mapping(uint256 => mapping(bytes32 => mapping(bytes32 => address)))) recoverGhost;
ghost bool forceZeroRecovery;

function recoverSummary(
    bytes32 messageForRecover,
    uint256 recoveryId,
    bytes32 signatureR,
    bytes32 signatureS
) returns (address) {
    if (forceZeroRecovery) {
        return 0;
    }
    if (forceMatchingAddresses) {
        return forcedMatchingAddress;
    }
    return recoverGhost[messageForRecover][recoveryId][signatureR][signatureS];
}

/// verify() must never revert for ABI-decodable typed inputs. Modulo the summarized
/// helper bodies, the boolean result is the only verifier-level failure channel.
rule verifyNeverReverts(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    verifyOptimized@withrevert(publicKeyX, signatureScalar, messageHash, nonceX);

    assert !lastReverted;
}

/// With the crypto primitives modeled deterministically, identical inputs yield
/// identical results.
rule verifyIsDeterministic(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    bool firstResult = verifyOptimized(publicKeyX, signatureScalar, messageHash, nonceX);
    bool secondResult = verifyOptimized(publicKeyX, signatureScalar, messageHash, nonceX);

    assert firstResult == secondResult;
}

/// The orchestration of the optimized verifier agrees with the reference implementation
/// on every input, for every possible behavior of the (summarized) crypto primitives:
/// same range checks, same short-circuits, same challenge negation, same argument wiring
/// into the recovery call, same final comparison.
rule matchesReferenceImplementation(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    bool optimizedResult = verifyOptimized(publicKeyX, signatureScalar, messageHash, nonceX);
    bool referenceResult = verifyReference(publicKeyX, signatureScalar, messageHash, nonceX);

    assert optimizedResult == referenceResult;
}

/// The witness entry point uses a boolean result for every ABI-decodable typed input.
rule verifyWithNonceYNeverReverts(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX,
    uint256 nonceY
) {
    verifyWithNonceYOptimized@withrevert(
        publicKeyX, signatureScalar, messageHash, nonceX, nonceY
    );

    assert !lastReverted;
}

/// The optimized witness path agrees with its assembly-free reference.
rule witnessMatchesReferenceImplementation(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX,
    uint256 nonceY
) {
    bool optimizedResult = verifyWithNonceYOptimized(
        publicKeyX, signatureScalar, messageHash, nonceX, nonceY
    );
    bool referenceResult = verifyWithNonceYReference(
        publicKeyX, signatureScalar, messageHash, nonceX, nonceY
    );

    assert optimizedResult == referenceResult;
}

/// `s = 0` is inside BIP340's scalar domain. This rule drives every summarized
/// primitive down an accepting path and proves neither verifier rejects zero early.
rule zeroSignatureScalarCanReachAcceptance(
    bytes32 messageHash
) {
    require liftValidGhost[GENERATOR_X()];
    require liftYGhost[GENERATOR_X()] == GENERATOR_EVEN_Y();
    require challengeOkGhost[GENERATOR_X()][1][messageHash];
    require challengeScalarGhost[GENERATOR_X()][1][messageHash] == 1;
    require forceMatchingAddresses;
    require !forceZeroRecovery;
    require forcedMatchingAddress != 0;

    assert verifyOptimized(1, 0, messageHash, GENERATOR_X());
    assert verifyWithNonceYOptimized(
        1, 0, messageHash, GENERATOR_X(), GENERATOR_EVEN_Y()
    );
}

/// Section 1.2 requires `e != 0`. Even with otherwise valid inputs and accepting
/// primitive summaries, both paths must stop before recovery when the challenge is zero.
rule rejectsZeroChallenge(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash
) {
    require publicKeyX > 0 && publicKeyX < SECP256K1_SCALAR_ORDER();
    require signatureScalar < SECP256K1_SCALAR_ORDER();
    require liftValidGhost[GENERATOR_X()];
    require liftYGhost[GENERATOR_X()] == GENERATOR_EVEN_Y();
    require challengeOkGhost[GENERATOR_X()][publicKeyX][messageHash];
    require challengeScalarGhost[GENERATOR_X()][publicKeyX][messageHash] == 0;
    require forceMatchingAddresses;
    require !forceZeroRecovery;
    require forcedMatchingAddress != 0;

    assert !verifyOptimized(publicKeyX, signatureScalar, messageHash, GENERATOR_X());
    assert !verifyWithNonceYOptimized(
        publicKeyX, signatureScalar, messageHash, GENERATOR_X(), GENERATOR_EVEN_Y()
    );
}

/// A failed recovery or a computed zero address is represented by the wrapper as
/// address zero. Both paths reject it even if the expected nonce address were also zero.
rule rejectsZeroRecoveryResult(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash
) {
    require publicKeyX > 0 && publicKeyX < SECP256K1_SCALAR_ORDER();
    require signatureScalar < SECP256K1_SCALAR_ORDER();
    require liftValidGhost[GENERATOR_X()];
    require liftYGhost[GENERATOR_X()] == GENERATOR_EVEN_Y();
    require challengeOkGhost[GENERATOR_X()][publicKeyX][messageHash];
    require challengeScalarGhost[GENERATOR_X()][publicKeyX][messageHash] > 0;
    require forceZeroRecovery;
    require !forceMatchingAddresses;
    require pointAddressGhost[GENERATOR_X()][GENERATOR_EVEN_Y()] == 0;

    assert !verifyOptimized(publicKeyX, signatureScalar, messageHash, GENERATOR_X());
    assert !verifyWithNonceYOptimized(
        publicKeyX, signatureScalar, messageHash, GENERATOR_X(), GENERATOR_EVEN_Y()
    );
}
