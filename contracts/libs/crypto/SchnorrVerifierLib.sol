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
///
/// Two entry points reconstruct `lift_x_even(Rx)` differently:
/// - `verify` computes the y-coordinate on-chain via a modular square root (modexp precompile).
/// - `verifyWithNonceY` accepts the y-coordinate as a caller-supplied witness and validates it
///   with two field multiplications, avoiding the modexp call entirely. Since EIP-7883 repriced
///   modexp, the witness path saves roughly 4500 gas of execution at the cost of one extra
///   32-byte argument.
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
        address noncePointAddress_;
        {
            (bool isNonceXOnCurve_, uint256 liftedEvenY_) = _liftXToEvenY(nonceX_);
            if (!isNonceXOnCurve_) {
                return false;
            }
            noncePointAddress_ = _pointAddress(nonceX_, liftedEvenY_);
        }

        // BIP340 challenge and sign-convention conversion:
        // e  = H_BIP340(Rx || Px || m) mod n
        // e* = n - e (mod n), so [e*]P = -[e]P
        uint256 negatedChallengeScalar_;
        {
            (bool challengeComputationSucceeded_, uint256 challengeScalar_) = _challengeBIP340(
                nonceX_,
                publicKeyX_,
                messageHash_
            );
            if (!challengeComputationSucceeded_) {
                return false;
            }
            negatedChallengeScalar_ = challengeScalar_ == 0
                ? 0
                : SECP256K1_SCALAR_ORDER - challengeScalar_;
        }

        // ecrecover argument mapping:
        // hash = n - (Px * s mod n)
        // v    = 27 + parity(P)
        // r    = Px
        // s    = e* * Px mod n
        // This recovers Q = [e*]P + [s]G.
        address recoveredAddress_ = _recoverAddress(
            bytes32(
                SECP256K1_SCALAR_ORDER -
                    mulmod(publicKeyX_, signatureScalar_, SECP256K1_SCALAR_ORDER)
            ),
            27 + uint256(publicKeyYParity_),
            bytes32(publicKeyX_),
            bytes32(mulmod(negatedChallengeScalar_, publicKeyX_, SECP256K1_SCALAR_ORDER))
        );

        // Accept only if recovered point matches lifted nonce point (and recovery succeeded).
        return recoveredAddress_ != address(0) && recoveredAddress_ == noncePointAddress_;
    }

    /// @notice Verifies a Schnorr signature like `verify`, but takes the nonce point y-coordinate
    /// as a caller-supplied witness instead of recomputing it on-chain.
    /// @dev Accepts the same inputs and enforces the same domains as `verify`, plus:
    /// - `nonceY` must be a field element, even, and satisfy `nonceY^2 == nonceX^3 + 7 (mod p)`.
    ///
    /// Soundness: for any on-curve `nonceX` there is exactly one point with even y, so the three
    /// witness checks pin `nonceY` to `lift_x_even(nonceX)` — the caller cannot supply any other
    /// value without failing verification. For an off-curve `nonceX` no witness exists and every
    /// call returns false, matching `verify`. The witness therefore changes gas, not behavior:
    /// `verifyWithNonceY(..., lift_x_even(nonceX)) == verify(...)` for all inputs.
    ///
    /// The y-coordinate is cheap to compute off-chain (any secp256k1 library) and replaces the
    /// modexp-precompile square root, whose EIP-7883 price dominates the non-ecrecover gas cost.
    /// The body deliberately duplicates the `verify` wiring instead of extracting shared private
    /// helpers: at `optimizer_runs = 200` such helpers are not inlined, and the extra internal
    /// calls would cost both entry points real gas.
    /// @param publicKeyX_ x-coordinate of public key point `P`.
    /// @param publicKeyYParity_ parity bit for public key y-coordinate (`0` even, `1` odd).
    /// @param signatureScalar_ Schnorr scalar `s`.
    /// @param messageHash_ 32-byte message digest used by the signer.
    /// @param nonceX_ x-coordinate `Rx` of the Schnorr nonce point.
    /// @param nonceY_ witness for the even y-coordinate of `lift_x_even(nonceX)`.
    /// @return isVerified_ true iff signature validates under this ecSchnorr* verifier.
    function verifyWithNonceY(
        uint256 publicKeyX_,
        uint8 publicKeyYParity_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_,
        uint256 nonceY_
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

        // Witness checks pinning `nonceY` to `R = lift_x_even(nonceX)`:
        // field membership and even parity select the canonical BIP340 branch...
        if (nonceY_ >= SECP256K1_FIELD_PRIME || (nonceY_ & 1) == 1) {
            return false;
        }

        // ...and the curve equation `y^2 == x^3 + 7 (mod p)` binds it to `nonceX`.
        if (
            mulmod(nonceY_, nonceY_, SECP256K1_FIELD_PRIME) !=
            addmod(
                mulmod(
                    mulmod(nonceX_, nonceX_, SECP256K1_FIELD_PRIME),
                    nonceX_,
                    SECP256K1_FIELD_PRIME
                ),
                7,
                SECP256K1_FIELD_PRIME
            )
        ) {
            return false;
        }

        address noncePointAddress_ = _pointAddress(nonceX_, nonceY_);

        // BIP340 challenge and sign-convention conversion:
        // e  = H_BIP340(Rx || Px || m) mod n
        // e* = n - e (mod n), so [e*]P = -[e]P
        uint256 negatedChallengeScalar_;
        {
            (bool challengeComputationSucceeded_, uint256 challengeScalar_) = _challengeBIP340(
                nonceX_,
                publicKeyX_,
                messageHash_
            );
            if (!challengeComputationSucceeded_) {
                return false;
            }
            // For e == 0 this yields n, which the mulmod below reduces to 0 — identical to
            // negating within Zn — so no zero-branch is needed.
            negatedChallengeScalar_ = SECP256K1_SCALAR_ORDER - challengeScalar_;
        }

        // ecrecover argument mapping:
        // hash = n - (Px * s mod n)
        // v    = 27 + parity(P)
        // r    = Px
        // s    = e* * Px mod n
        // This recovers Q = [e*]P + [s]G.
        address recoveredAddress_ = _recoverAddress(
            bytes32(
                SECP256K1_SCALAR_ORDER -
                    mulmod(publicKeyX_, signatureScalar_, SECP256K1_SCALAR_ORDER)
            ),
            27 + uint256(publicKeyYParity_),
            bytes32(publicKeyX_),
            bytes32(mulmod(negatedChallengeScalar_, publicKeyX_, SECP256K1_SCALAR_ORDER))
        );

        // Accept only if recovered point matches the witnessed nonce point (and recovery succeeded).
        return recoveredAddress_ != address(0) && recoveredAddress_ == noncePointAddress_;
    }

    /// @dev Computes BIP340 challenge scalar:
    /// `challenge = SHA256(tagHash || tagHash || nonceX || publicKeyX || messageHash) mod n`.
    /// Uses SHA-256 precompile (`0x02`) directly from assembly to keep the input layout explicit.
    /// Returns `(false, 0)` if the precompile call does not return a 32-byte output.
    function _challengeBIP340(
        uint256 nonceX_,
        uint256 publicKeyX_,
        bytes32 messageHash_
    ) private view returns (bool challengeComputationSucceeded_, uint256 challengeScalar_) {
        assembly ("memory-safe") {
            let shaInputPointer := mload(0x40)

            // Build 160-byte preimage:
            // [tagHash][tagHash][nonceX][publicKeyX][messageHash].
            mstore(shaInputPointer, BIP340_CHALLENGE_TAG_HASH)
            mstore(add(shaInputPointer, 0x20), BIP340_CHALLENGE_TAG_HASH)
            mstore(add(shaInputPointer, 0x40), nonceX_)
            mstore(add(shaInputPointer, 0x60), publicKeyX_)
            mstore(add(shaInputPointer, 0x80), messageHash_)

            // SHA-256 precompile (0x02): input=160 bytes, 32-byte digest lands in scratch space.
            let shaCallSucceeded := staticcall(gas(), 0x02, shaInputPointer, 0xa0, 0x00, 0x20)
            challengeComputationSucceeded_ := and(shaCallSucceeded, eq(returndatasize(), 0x20))
            if challengeComputationSucceeded_ {
                // Reduce digest into scalar field Zn.
                challengeScalar_ := mod(mload(0x00), SECP256K1_SCALAR_ORDER)
            }
        }
    }

    /// @dev Lifts `pointX` to the unique even-y secp256k1 point if it exists.
    /// Curve is `y^2 = x^3 + 7 (mod p)`.
    /// For secp256k1 (`p % 4 == 3`), square root is `y = c^((p+1)/4) mod p`.
    /// This exponent is precomputed as `SECP256K1_SQRT_EXPONENT`.
    /// Returns `(false, 0)` when `pointX` is not a quadratic residue on the curve.
    function _liftXToEvenY(
        uint256 pointX_
    ) private view returns (bool pointIsValid, uint256 liftedEvenY) {
        // c = x^3 + 7 mod p.
        uint256 curveEquationValue_ = addmod(
            mulmod(
                mulmod(pointX_, pointX_, SECP256K1_FIELD_PRIME),
                pointX_,
                SECP256K1_FIELD_PRIME
            ),
            7,
            SECP256K1_FIELD_PRIME
        );

        // For p % 4 == 3 curves, sqrt(c) = c^((p+1)/4) mod p.
        (bool modExpSucceeded_, uint256 candidateY_) = _modExp(
            curveEquationValue_,
            SECP256K1_SQRT_EXPONENT,
            SECP256K1_FIELD_PRIME
        );
        if (!modExpSucceeded_) {
            return (false, 0);
        }

        // Reject non-residue x values.
        if (mulmod(candidateY_, candidateY_, SECP256K1_FIELD_PRIME) != curveEquationValue_) {
            return (false, 0);
        }

        // Canonicalize to even-y branch.
        if ((candidateY_ & 1) == 1) {
            candidateY_ = SECP256K1_FIELD_PRIME - candidateY_;
        }

        return (true, candidateY_);
    }

    /// @dev Computes Ethereum address for affine point `(x, y)`:
    /// `address = last_20_bytes(keccak256(x || y))`.
    function _pointAddress(
        uint256 pointX_,
        uint256 pointY_
    ) private pure returns (address pointAddress_) {
        assembly ("memory-safe") {
            // Hash 64-byte affine coordinate payload from scratch space.
            mstore(0x00, pointX_)
            mstore(0x20, pointY_)
            // Truncate to Ethereum address width (160 bits).
            pointAddress_ := and(keccak256(0x00, 0x40), 0xffffffffffffffffffffffffffffffffffffffff)
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
            let modExpInputPointer := mload(0x40)

            // Modexp precompile ABI:
            // [baseLen][expLen][modLen][base][exp][mod].
            mstore(modExpInputPointer, 0x20)
            mstore(add(modExpInputPointer, 0x20), 0x20)
            mstore(add(modExpInputPointer, 0x40), 0x20)
            mstore(add(modExpInputPointer, 0x60), baseValue_)
            mstore(add(modExpInputPointer, 0x80), exponentValue_)
            mstore(add(modExpInputPointer, 0xa0), modulusValue_)

            // Compute base^exp mod modulus via precompile 0x05, result lands in scratch space.
            let modExpCallSucceeded := staticcall(
                gas(),
                0x05,
                modExpInputPointer,
                0xc0,
                0x00,
                0x20
            )
            callSucceeded_ := and(modExpCallSucceeded, eq(returndatasize(), 0x20))
            if callSucceeded_ {
                exponentiationResult_ := mload(0x00)
            }
        }
    }

    /// @dev Thin `ecrecover` wrapper over precompile `0x01` with explicit input layout:
    /// `[hash][v][r][s]` (each 32 bytes, with `v` in low byte).
    /// Returns `address(0)` on precompile failure.
    function _recoverAddress(
        bytes32 messageForRecover_,
        uint256 recoveryId_,
        bytes32 signatureR_,
        bytes32 signatureS_
    ) private view returns (address recoveredAddress_) {
        assembly ("memory-safe") {
            let ecrecoverInputPointer := mload(0x40)

            // ECDSA recovery input words: [hash][v][r][s].
            mstore(ecrecoverInputPointer, messageForRecover_)
            mstore(add(ecrecoverInputPointer, 0x20), recoveryId_)
            mstore(add(ecrecoverInputPointer, 0x40), signatureR_)
            mstore(add(ecrecoverInputPointer, 0x60), signatureS_)

            // On success, the recovered address lands in scratch space.
            let recoverCallSucceeded := staticcall(
                gas(),
                0x01,
                ecrecoverInputPointer,
                0x80,
                0x00,
                0x20
            )
            if and(recoverCallSucceeded, eq(returndatasize(), 0x20)) {
                recoveredAddress_ := and(mload(0x00), 0xffffffffffffffffffffffffffffffffffffffff)
            }
        }
    }
}
