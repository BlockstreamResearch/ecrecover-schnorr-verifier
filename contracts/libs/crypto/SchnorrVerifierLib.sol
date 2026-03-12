// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @title SchnorrVerifierLib
/// @notice Verifies BIP340-compatible Schnorr signatures on secp256k1 via the `ecrecover` precompile.
/// @dev This library implements the ecSchnorr* construction:
///
/// - BIP340 verification equation:
///   `[s]G - [e]P = R`, where `e = H_BIP340(Rx || Px || m) mod n`.
/// - ecSchnorr* rewritten equation:
///   `[s]G + [e*]P = R`, where `e* = n - e mod n`.
///
/// The EVM precompile at address `0x01` computes ECDSA recovery, but with carefully chosen
/// calldata it can be repurposed to compute `Q = [e*]P + [s]G` and return `addr(Q)`.
/// The verifier then checks:
/// `addr([e*]P + [s]G) == addr(lift_x_even(Rx))`.
library SchnorrVerifierLib {
    uint256 internal constant SECP256K1_FIELD_PRIME =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant SECP256K1_SCALAR_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 private constant SECP256K1_SQRT_EXPONENT =
        0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C;
    bytes32 private constant BIP340_CHALLENGE_TAG_HASH =
        hex"7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c";

    /// @notice Verifies a Schnorr signature represented as `(nonceX, signatureScalar)` against an x-only key.
    /// @dev Inputs and checks:
    /// - `publicKeyX` is constrained to `[1, n-1]` because it is passed through the ECDSA `r` slot.
    /// - `publicKeyYParity` must be 0 or 1 and selects `lift_x_parity(publicKeyX)` for the recovered key point.
    /// - `signatureScalar` must be in `[1, n-1]`.
    /// - `nonceX` must be in `[1, p-1]` and lie on secp256k1 (validated via modular square root).
    ///
    /// Workflow:
    /// 1. Lift `nonceX` to even-y point and derive `noncePointAddress = addr(lift_x_even(nonceX))`.
    /// 2. Compute BIP340 challenge `e = H_BIP340(nonceX || publicKeyX || messageHash) mod n`.
    /// 3. Set `e* = n - e mod n`.
    /// 4. Call `ecrecover` with encoded values so recovered point is `[e*]P + [s]G`.
    /// 5. Return true iff recovered address equals `noncePointAddress`.
    ///
    /// If `ecrecover` fails, it yields `address(0)` and verification fails.
    /// @param publicKeyX_ x-coordinate of public key point `P`.
    /// @param publicKeyYParity_ parity bit for public key y-coordinate (`0` even, `1` odd).
    /// @param signatureScalar_ Schnorr scalar `s`.
    /// @param messageHash_ 32-byte message digest used by the signer.
    /// @param nonceX_ x-coordinate `Rx` of the Schnorr nonce point.
    /// @return isVerified_ true iff signature validates under this ecSchnorr* verifier.
    function verify(
        uint256 publicKeyX_,
        uint8 publicKeyYParity_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_
    ) internal view returns (bool isVerified_) {
        // Public key x is routed through the ECDSA `r` slot, which accepts
        // only scalars in `[1, n-1]`.
        if (publicKeyX_ == 0 || publicKeyX_ >= SECP256K1_SCALAR_ORDER) {
            return false;
        }

        // Signature scalar must be in Zn*.
        if (signatureScalar_ == 0 || signatureScalar_ >= SECP256K1_SCALAR_ORDER) {
            return false;
        }

        // Nonce x-coordinate must be a field element and non-zero.
        if (nonceX_ == 0 || nonceX_ >= SECP256K1_FIELD_PRIME) {
            return false;
        }

        // Parity bit must encode one of the two y branches.
        if (publicKeyYParity_ > 1) {
            return false;
        }

        // Reconstruct `R = lift_x_even(nonceX)` and its Ethereum address.
        address noncePointAddress;
        {
            (bool isNonceXOnCurve, uint256 liftedEvenY) = _liftXToEvenY(nonceX_);
            if (!isNonceXOnCurve) {
                return false;
            }
            noncePointAddress = _pointAddress(nonceX_, liftedEvenY);
        }

        // BIP340 challenge and sign-convention conversion:
        // e  = H(Rx || Px || m) mod n
        // e* = n - e (mod n), so [e*]P = -[e]P
        uint256 negatedChallengeScalar;
        {
            (bool challengeComputationSucceeded, uint256 challengeScalar) = _challengeBIP340(
                nonceX_,
                publicKeyX_,
                messageHash_
            );
            if (!challengeComputationSucceeded) {
                return false;
            }
            negatedChallengeScalar = challengeScalar == 0
                ? 0
                : SECP256K1_SCALAR_ORDER - challengeScalar;
        }

        // ecrecover argument mapping:
        // hash = n - (Px * s mod n)
        // v    = 27 + parity(P)
        // r    = Px
        // s    = e* * Px mod n
        // This recovers Q = [e*]P + [s]G.
        address recoveredAddress = _recoverAddress(
            bytes32(
                SECP256K1_SCALAR_ORDER -
                    mulmod(publicKeyX_, signatureScalar_, SECP256K1_SCALAR_ORDER)
            ),
            uint8(27 + uint256(publicKeyYParity_)),
            bytes32(publicKeyX_),
            bytes32(mulmod(negatedChallengeScalar, publicKeyX_, SECP256K1_SCALAR_ORDER))
        );

        // Accept iff recovered point matches lifted nonce point (and recovery succeeded).
        return recoveredAddress != address(0) && recoveredAddress == noncePointAddress;
    }

    /// @dev Computes BIP340 challenge scalar:
    /// `challenge = SHA256(tagHash || tagHash || nonceX || publicKeyX || messageHash) mod n`.
    /// Uses SHA-256 precompile (`0x02`) directly from assembly to keep calldata layout explicit.
    /// Returns `(false, 0)` if the precompile call does not return a 32-byte output.
    function _challengeBIP340(
        uint256 nonceX,
        uint256 publicKeyX,
        bytes32 messageHash
    ) internal view returns (bool challengeComputationSucceeded, uint256 challengeScalar) {
        assembly ("memory-safe") {
            let freeMemoryPointer := mload(0x40)
            let shaInputPointer := freeMemoryPointer
            let shaOutputPointer := add(shaInputPointer, 0xa0)

            // Build 160-byte preimage:
            // [tagHash][tagHash][nonceX][publicKeyX][messageHash].
            mstore(shaInputPointer, BIP340_CHALLENGE_TAG_HASH)
            mstore(add(shaInputPointer, 0x20), BIP340_CHALLENGE_TAG_HASH)
            mstore(add(shaInputPointer, 0x40), nonceX)
            mstore(add(shaInputPointer, 0x60), publicKeyX)
            mstore(add(shaInputPointer, 0x80), messageHash)

            // SHA-256 precompile (0x02): input=160 bytes, output=32 bytes.
            let shaCallSucceeded := staticcall(
                gas(),
                0x02,
                shaInputPointer,
                0xa0,
                shaOutputPointer,
                0x20
            )
            challengeComputationSucceeded := and(shaCallSucceeded, eq(returndatasize(), 0x20))
            if challengeComputationSucceeded {
                // Reduce digest into scalar field Zn.
                challengeScalar := mod(mload(shaOutputPointer), SECP256K1_SCALAR_ORDER)
            }

            mstore(0x40, freeMemoryPointer)
        }
    }

    /// @dev Lifts `pointX` to the unique even-y secp256k1 point if it exists.
    /// Curve is `y^2 = x^3 + 7 (mod p)`.
    /// For secp256k1 (`p % 4 == 3`), square root is `y = c^((p+1)/4) mod p`.
    /// This exponent is precomputed as `SECP256K1_SQRT_EXPONENT`.
    /// Returns `(false, 0)` when `pointX` is not a quadratic residue on the curve.
    function _liftXToEvenY(
        uint256 pointX
    ) internal view returns (bool pointIsValid, uint256 liftedEvenY) {
        // c = x^3 + 7 mod p.
        uint256 curveEquationValue = addmod(
            mulmod(mulmod(pointX, pointX, SECP256K1_FIELD_PRIME), pointX, SECP256K1_FIELD_PRIME),
            7,
            SECP256K1_FIELD_PRIME
        );

        // For p % 4 == 3 curves, sqrt(c) = c^((p+1)/4) mod p.
        (bool modExpSucceeded, uint256 candidateY) = _modExp(
            curveEquationValue,
            SECP256K1_SQRT_EXPONENT,
            SECP256K1_FIELD_PRIME
        );
        if (!modExpSucceeded) {
            return (false, 0);
        }

        // Reject non-residue x values.
        if (mulmod(candidateY, candidateY, SECP256K1_FIELD_PRIME) != curveEquationValue) {
            return (false, 0);
        }

        // Canonicalize to even-y branch.
        if ((candidateY & 1) == 1) {
            candidateY = SECP256K1_FIELD_PRIME - candidateY;
        }

        return (true, candidateY);
    }

    /// @dev Computes Ethereum address for affine point `(x, y)`:
    /// `address = last_20_bytes(keccak256(x || y))`.
    function _pointAddress(
        uint256 pointX_,
        uint256 pointY_
    ) internal pure returns (address pointAddress_) {
        assembly ("memory-safe") {
            let freeMemoryPointer := mload(0x40)
            // Hash 64-byte affine coordinate payload.
            mstore(freeMemoryPointer, pointX_)
            mstore(add(freeMemoryPointer, 0x20), pointY_)
            // Truncate to Ethereum address width (160 bits).
            pointAddress_ := and(
                keccak256(freeMemoryPointer, 0x40),
                0xffffffffffffffffffffffffffffffffffffffff
            )
            mstore(0x40, freeMemoryPointer)
        }
    }

    /// @dev Modular exponentiation wrapper over precompile `0x05`.
    /// Input buffer format is:
    /// `[len(base)=32][len(exp)=32][len(mod)=32][base][exp][mod]`.
    /// Returns `(false, 0)` if precompile call fails or does not return 32 bytes.
    function _modExp(
        uint256 baseValue_,
        uint256 exponentValue_,
        uint256 modulusValue_
    ) private view returns (bool callSucceeded_, uint256 exponentiationResult_) {
        assembly ("memory-safe") {
            let freeMemoryPointer := mload(0x40)
            let modExpInputPointer := freeMemoryPointer
            let modExpOutputPointer := add(modExpInputPointer, 0xc0)

            // Modexp precompile ABI:
            // [baseLen][expLen][modLen][base][exp][mod].
            mstore(modExpInputPointer, 0x20)
            mstore(add(modExpInputPointer, 0x20), 0x20)
            mstore(add(modExpInputPointer, 0x40), 0x20)
            mstore(add(modExpInputPointer, 0x60), baseValue_)
            mstore(add(modExpInputPointer, 0x80), exponentValue_)
            mstore(add(modExpInputPointer, 0xa0), modulusValue_)

            // Compute base^exp mod modulus via precompile 0x05.
            let modExpCallSucceeded := staticcall(
                gas(),
                0x05,
                modExpInputPointer,
                0xc0,
                modExpOutputPointer,
                0x20
            )
            callSucceeded_ := and(modExpCallSucceeded, eq(returndatasize(), 0x20))
            if callSucceeded_ {
                exponentiationResult_ := mload(modExpOutputPointer)
            }

            mstore(0x40, freeMemoryPointer)
        }
    }

    /// @dev Thin `ecrecover` wrapper over precompile `0x01` with explicit calldata layout:
    /// `[hash][v][r][s]` (each 32 bytes, with `v` in low byte).
    /// Returns `address(0)` on precompile failure.
    function _recoverAddress(
        bytes32 messageForRecover_,
        uint8 recoveryId_,
        bytes32 signatureR_,
        bytes32 signatureS_
    ) private view returns (address recoveredAddress) {
        assembly ("memory-safe") {
            let freeMemoryPointer := mload(0x40)
            let ecrecoverInputPointer := freeMemoryPointer
            let ecrecoverOutputPointer := add(ecrecoverInputPointer, 0x80)

            // ECDSA recovery calldata words: [hash][v][r][s].
            mstore(ecrecoverInputPointer, messageForRecover_)
            mstore(add(ecrecoverInputPointer, 0x20), and(recoveryId_, 0xff))
            mstore(add(ecrecoverInputPointer, 0x40), signatureR_)
            mstore(add(ecrecoverInputPointer, 0x60), signatureS_)

            // On success, returned word contains the recovered address.
            let recoverCallSucceeded := staticcall(
                gas(),
                0x01,
                ecrecoverInputPointer,
                0x80,
                ecrecoverOutputPointer,
                0x20
            )
            if and(recoverCallSucceeded, eq(returndatasize(), 0x20)) {
                recoveredAddress := and(
                    mload(ecrecoverOutputPointer),
                    0xffffffffffffffffffffffffffffffffffffffff
                )
            }

            mstore(0x40, freeMemoryPointer)
        }
    }
}
