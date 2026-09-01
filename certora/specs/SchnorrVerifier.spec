/*
 * Certora specification for SchnorrVerifierLib (via SchnorrVerifierHarness).
 *
 * Scope note: the prover models the cryptographic primitives (ecrecover, SHA-256,
 * keccak256, modexp) as uninterpreted/summarized functions, so these rules verify the
 * Solidity/assembly plumbing of the verifier — input-domain handling, non-reverting
 * behavior, and equivalence with the assembly-free reference implementation — not the
 * cryptographic soundness of the ecSchnorr* construction itself (the accompanying paper
 * supplies a reduction conditional on RPAC and application-level integration requirements).
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
}

definition SECP256K1_FIELD_PRIME() returns uint256 =
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
definition SECP256K1_SCALAR_ORDER() returns uint256 =
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

/// verify() must never revert for ABI-decodable typed inputs. Callers rely on the
/// boolean result being the only verifier-level failure channel.
rule verifyNeverReverts(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    verifyOptimized@withrevert(publicKeyX, signatureScalar, messageHash, nonceX);

    assert !lastReverted;
}

/// The public key x-coordinate is routed through the ECDSA `r` slot and must be
/// rejected outside `[1, n-1]`.
rule rejectsPublicKeyXOutsideScalarField(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    require publicKeyX == 0 || publicKeyX >= SECP256K1_SCALAR_ORDER();

    assert !verifyOptimized(publicKeyX, signatureScalar, messageHash, nonceX);
}

/// BIP340 permits zero and rejects only signature scalars outside `[0, n-1]`.
rule rejectsSignatureScalarOutsideScalarField(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    require signatureScalar >= SECP256K1_SCALAR_ORDER();

    assert !verifyOptimized(publicKeyX, signatureScalar, messageHash, nonceX);
}

/// The nonce x-coordinate must be rejected outside `[1, p-1]`.
rule rejectsNonceXOutsideBaseField(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    require nonceX == 0 || nonceX >= SECP256K1_FIELD_PRIME();

    assert !verifyOptimized(publicKeyX, signatureScalar, messageHash, nonceX);
}

/// Contrapositive of the domain rules in one shot: an accepted input is always
/// well-formed. Guards against any future refactor reordering or dropping a check.
rule acceptImpliesWellFormedInput(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    bool isVerified = verifyOptimized(publicKeyX, signatureScalar, messageHash, nonceX);

    assert isVerified => (
        publicKeyX > 0 && publicKeyX < SECP256K1_SCALAR_ORDER() &&
        signatureScalar < SECP256K1_SCALAR_ORDER() &&
        nonceX > 0 && nonceX < SECP256K1_FIELD_PRIME()
    );
}

/// A witness outside the base field cannot identify a nonce point.
rule rejectsNonceYOutsideBaseField(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX,
    uint256 nonceY
) {
    require nonceY >= SECP256K1_FIELD_PRIME();

    assert !verifyWithNonceYOptimized(
        publicKeyX, signatureScalar, messageHash, nonceX, nonceY
    );
}

/// The BIP340 nonce witness must select the even y-coordinate.
rule rejectsOddNonceY(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX,
    uint256 nonceY
) {
    require nonceY % 2 == 1;

    assert !verifyWithNonceYOptimized(
        publicKeyX, signatureScalar, messageHash, nonceX, nonceY
    );
}

/// Acceptance through the witness path implies every cheaply expressible domain check.
/// The curve equation itself is checked concretely by the implementation and differential tests.
rule witnessAcceptImpliesWellFormedInput(
    uint256 publicKeyX,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX,
    uint256 nonceY
) {
    bool isVerified = verifyWithNonceYOptimized(
        publicKeyX, signatureScalar, messageHash, nonceX, nonceY
    );

    assert isVerified => (
        publicKeyX > 0 && publicKeyX < SECP256K1_SCALAR_ORDER() &&
        signatureScalar < SECP256K1_SCALAR_ORDER() &&
        nonceX > 0 && nonceX < SECP256K1_FIELD_PRIME() &&
        nonceY < SECP256K1_FIELD_PRIME() &&
        nonceY % 2 == 0
    );
}

/// The verifier reads no storage, so the same input always yields the same result.
/// Also fails if any precompile interaction is modeled non-deterministically, which
/// would undermine the equivalence rule below.
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

/// Flagship rule: the optimized assembly implementation agrees with the assembly-free
/// reference implementation on every input. Both sides invoke the same primitives with
/// the same arguments, so any counterexample points at a bug in the hand-written
/// memory/scratch-space handling of `SchnorrVerifierLib`.
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
