/*
 * Certora specification for SchnorrVerifierLib (via SchnorrVerifierHarness).
 *
 * Scope note: the prover models the cryptographic primitives (ecrecover, SHA-256,
 * keccak256, modexp) as uninterpreted/summarized functions, so these rules verify the
 * Solidity/assembly plumbing of the verifier — input-domain handling, non-reverting
 * behavior, and equivalence with the assembly-free reference implementation — not the
 * cryptographic soundness of the ecSchnorr* construction itself (that argument lives in
 * the accompanying paper).
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
}

definition SECP256K1_FIELD_PRIME() returns uint256 =
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
definition SECP256K1_SCALAR_ORDER() returns uint256 =
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

/// verify() must never revert, no matter the input. Callers rely on the boolean
/// result being the only failure channel.
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

/// The public key x-coordinate is routed through the ECDSA `r` slot and must be
/// rejected outside `[1, n-1]`.
rule rejectsPublicKeyXOutsideScalarField(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    require publicKeyX == 0 || publicKeyX >= SECP256K1_SCALAR_ORDER();

    assert !verifyOptimized(publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX);
}

/// The signature scalar must be rejected outside `[1, n-1]`.
rule rejectsSignatureScalarOutsideScalarField(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    require signatureScalar == 0 || signatureScalar >= SECP256K1_SCALAR_ORDER();

    assert !verifyOptimized(publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX);
}

/// The nonce x-coordinate must be rejected outside `[1, p-1]`.
rule rejectsNonceXOutsideBaseField(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    require nonceX == 0 || nonceX >= SECP256K1_FIELD_PRIME();

    assert !verifyOptimized(publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX);
}

/// The parity bit must be rejected outside {0, 1}.
rule rejectsInvalidParity(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    require publicKeyYParity > 1;

    assert !verifyOptimized(publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX);
}

/// Contrapositive of the domain rules in one shot: an accepted input is always
/// well-formed. Guards against any future refactor reordering or dropping a check.
rule acceptImpliesWellFormedInput(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX
) {
    bool isVerified = verifyOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX
    );

    assert isVerified => (
        publicKeyX > 0 && publicKeyX < SECP256K1_SCALAR_ORDER() &&
        signatureScalar > 0 && signatureScalar < SECP256K1_SCALAR_ORDER() &&
        nonceX > 0 && nonceX < SECP256K1_FIELD_PRIME() &&
        publicKeyYParity <= 1
    );
}

/// The verifier reads no storage, so the same input always yields the same result.
/// Also fails if any precompile interaction is modeled non-deterministically, which
/// would undermine the equivalence rule below.
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

/// The witness-based entry point shares every input domain with `verify`; all four
/// domain violations must be rejected regardless of the witness value.
rule witnessRejectsSharedDomainViolations(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX,
    uint256 nonceY
) {
    require (publicKeyX == 0 || publicKeyX >= SECP256K1_SCALAR_ORDER())
        || (signatureScalar == 0 || signatureScalar >= SECP256K1_SCALAR_ORDER())
        || (nonceX == 0 || nonceX >= SECP256K1_FIELD_PRIME())
        || publicKeyYParity > 1;

    assert !verifyWithNonceYOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX, nonceY
    );
}

/// The nonce y-coordinate witness must be rejected outside `[0, p-1]`.
rule rejectsNonceYOutsideBaseField(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX,
    uint256 nonceY
) {
    require nonceY >= SECP256K1_FIELD_PRIME();

    assert !verifyWithNonceYOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX, nonceY
    );
}

/// The nonce y-coordinate witness must be rejected when odd: BIP340 pins the nonce
/// point to the even-y branch, and accepting the odd mirror would verify against `-R`.
rule rejectsOddNonceY(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX,
    uint256 nonceY
) {
    require nonceY % 2 == 1;

    assert !verifyWithNonceYOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX, nonceY
    );
}

/// The nonce y-coordinate witness must satisfy the curve equation
/// `y^2 == x^3 + 7 (mod p)`; anything else cannot be `lift_x_even(nonceX)`.
rule rejectsOffCurveNonceY(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX,
    uint256 nonceY
) {
    require (nonceY * nonceY) % SECP256K1_FIELD_PRIME()
        != (nonceX * nonceX * nonceX + 7) % SECP256K1_FIELD_PRIME();

    assert !verifyWithNonceYOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX, nonceY
    );
}

/// Contrapositive of the witness-path domain rules in one shot: an accepted input is
/// always well-formed and carries the unique even-y on-curve witness.
rule witnessAcceptImpliesWellFormedInput(
    uint256 publicKeyX,
    uint8 publicKeyYParity,
    uint256 signatureScalar,
    bytes32 messageHash,
    uint256 nonceX,
    uint256 nonceY
) {
    bool isVerified = verifyWithNonceYOptimized(
        publicKeyX, publicKeyYParity, signatureScalar, messageHash, nonceX, nonceY
    );

    assert isVerified => (
        publicKeyX > 0 && publicKeyX < SECP256K1_SCALAR_ORDER() &&
        signatureScalar > 0 && signatureScalar < SECP256K1_SCALAR_ORDER() &&
        nonceX > 0 && nonceX < SECP256K1_FIELD_PRIME() &&
        publicKeyYParity <= 1 &&
        nonceY < SECP256K1_FIELD_PRIME() &&
        nonceY % 2 == 0 &&
        (nonceY * nonceY) % SECP256K1_FIELD_PRIME()
            == (nonceX * nonceX * nonceX + 7) % SECP256K1_FIELD_PRIME()
    );
}

/// Flagship rule: the optimized assembly implementation agrees with the assembly-free
/// reference implementation on every input. Both sides invoke the same primitives with
/// the same arguments, so any counterexample points at a bug in the hand-written
/// memory/scratch-space handling of `SchnorrVerifierLib`.
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
