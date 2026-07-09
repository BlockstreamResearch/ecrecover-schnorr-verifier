// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {SchnorrVerifierLib} from "../../contracts/libs/crypto/SchnorrVerifierLib.sol";

/// @title SchnorrVerifierHarness
/// @notice Certora verification harness. Exposes the optimized library verifier next to a
/// deliberately naive, assembly-free reference implementation of the same ecSchnorr*
/// construction. The prover checks that both agree on every input (see
/// `certora/specs/SchnorrVerifier.spec`), so any divergence introduced by the hand-written
/// assembly in `SchnorrVerifierLib` becomes a counterexample.
/// @dev The reference implementation intentionally mirrors the failure semantics of the
/// optimized code: precompile calls are made with explicit `staticcall`s that return `false`
/// on failure instead of reverting, matching the library's non-reverting design.
/// This contract is verification-only and must never be deployed.
contract SchnorrVerifierHarness {
    uint256 internal constant SECP256K1_FIELD_PRIME =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant SECP256K1_SCALAR_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant SECP256K1_SQRT_EXPONENT =
        0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C;
    bytes32 internal constant BIP340_CHALLENGE_TAG_HASH =
        hex"7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c";

    address internal constant SHA256_PRECOMPILE = address(0x02);
    address internal constant MODEXP_PRECOMPILE = address(0x05);

    /// @notice The optimized implementation under verification.
    function verifyOptimized(
        uint256 publicKeyX_,
        uint8 publicKeyYParity_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_
    ) external view returns (bool isVerified_) {
        return
            SchnorrVerifierLib.verify(
                publicKeyX_,
                publicKeyYParity_,
                signatureScalar_,
                messageHash_,
                nonceX_
            );
    }

    /// @notice Assembly-free reference implementation of the ecSchnorr* verifier.
    /// @dev Kept in lockstep with the documented workflow of `SchnorrVerifierLib.verify`:
    /// 1. Range-check all inputs.
    /// 2. Lift `nonceX` to the even-y point and derive its Ethereum address.
    /// 3. Compute the BIP340 challenge `e` and negate it into `e*`.
    /// 4. Recover `addr([e*]P + [s]G)` via the `ecrecover` builtin.
    /// 5. Accept only on a non-zero address match.
    function verifyReference(
        uint256 publicKeyX_,
        uint8 publicKeyYParity_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_
    ) external view returns (bool isVerified_) {
        if (publicKeyX_ == 0 || publicKeyX_ >= SECP256K1_SCALAR_ORDER) {
            return false;
        }
        if (signatureScalar_ == 0 || signatureScalar_ >= SECP256K1_SCALAR_ORDER) {
            return false;
        }
        if (nonceX_ == 0 || nonceX_ >= SECP256K1_FIELD_PRIME) {
            return false;
        }
        if (publicKeyYParity_ > 1) {
            return false;
        }

        address noncePointAddress_;
        {
            (bool isNonceXOnCurve_, uint256 liftedEvenY_) = _liftXToEvenYReference(nonceX_);
            if (!isNonceXOnCurve_) {
                return false;
            }
            noncePointAddress_ = _pointAddressReference(nonceX_, liftedEvenY_);
        }

        uint256 negatedChallengeScalar_;
        {
            (bool challengeComputationSucceeded_, uint256 challengeScalar_) = _challengeReference(
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

        address recoveredAddress_ = _recoverReference(
            bytes32(
                SECP256K1_SCALAR_ORDER -
                    mulmod(publicKeyX_, signatureScalar_, SECP256K1_SCALAR_ORDER)
            ),
            27 + uint256(publicKeyYParity_),
            bytes32(publicKeyX_),
            bytes32(mulmod(negatedChallengeScalar_, publicKeyX_, SECP256K1_SCALAR_ORDER))
        );

        return recoveredAddress_ != address(0) && recoveredAddress_ == noncePointAddress_;
    }

    /// @dev Reference point address: `last_20_bytes(keccak256(x || y))`. Wrapped as an
    /// internal function so the modular spec can pair it with `SchnorrVerifierLib._pointAddress`
    /// under a shared deterministic summary.
    function _pointAddressReference(
        uint256 pointX_,
        uint256 pointY_
    ) internal pure returns (address pointAddress_) {
        return address(uint160(uint256(keccak256(abi.encode(pointX_, pointY_)))));
    }

    /// @dev Reference ECDSA recovery through the `ecrecover` builtin. Wrapped as an internal
    /// function so the modular spec can pair it with `SchnorrVerifierLib._recoverAddress`
    /// under a shared deterministic summary.
    function _recoverReference(
        bytes32 messageForRecover_,
        uint256 recoveryId_,
        bytes32 signatureR_,
        bytes32 signatureS_
    ) internal view returns (address recoveredAddress_) {
        return ecrecover(messageForRecover_, uint8(recoveryId_), signatureR_, signatureS_);
    }

    /// @dev Reference BIP340 challenge: `SHA256(tag || tag || Rx || Px || m) mod n` through a
    /// plain `staticcall` so a failing precompile maps to `(false, 0)` exactly like the library.
    function _challengeReference(
        uint256 nonceX_,
        uint256 publicKeyX_,
        bytes32 messageHash_
    ) internal view returns (bool challengeComputationSucceeded_, uint256 challengeScalar_) {
        (bool callSucceeded_, bytes memory digest_) = SHA256_PRECOMPILE.staticcall(
            bytes.concat(
                BIP340_CHALLENGE_TAG_HASH,
                BIP340_CHALLENGE_TAG_HASH,
                bytes32(nonceX_),
                bytes32(publicKeyX_),
                messageHash_
            )
        );
        if (!callSucceeded_ || digest_.length != 32) {
            return (false, 0);
        }

        return (true, uint256(bytes32(digest_)) % SECP256K1_SCALAR_ORDER);
    }

    /// @dev Reference even-y lift: `y = (x^3 + 7)^((p+1)/4) mod p` via the modexp precompile,
    /// rejecting non-residues and canonicalizing to the even branch.
    function _liftXToEvenYReference(
        uint256 pointX_
    ) internal view returns (bool pointIsValid_, uint256 liftedEvenY_) {
        uint256 curveEquationValue_ = addmod(
            mulmod(
                mulmod(pointX_, pointX_, SECP256K1_FIELD_PRIME),
                pointX_,
                SECP256K1_FIELD_PRIME
            ),
            7,
            SECP256K1_FIELD_PRIME
        );

        (bool callSucceeded_, bytes memory output_) = MODEXP_PRECOMPILE.staticcall(
            abi.encode(
                uint256(32),
                uint256(32),
                uint256(32),
                curveEquationValue_,
                SECP256K1_SQRT_EXPONENT,
                SECP256K1_FIELD_PRIME
            )
        );
        if (!callSucceeded_ || output_.length != 32) {
            return (false, 0);
        }

        uint256 candidateY_ = abi.decode(output_, (uint256));
        if (mulmod(candidateY_, candidateY_, SECP256K1_FIELD_PRIME) != curveEquationValue_) {
            return (false, 0);
        }

        if ((candidateY_ & 1) == 1) {
            candidateY_ = SECP256K1_FIELD_PRIME - candidateY_;
        }

        return (true, candidateY_);
    }
}
