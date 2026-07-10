// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";

import {SchnorrVerifierLib} from "../contracts/libs/crypto/SchnorrVerifierLib.sol";

/// @notice Measures execution gas of the internal library verifiers with `gasleft()` deltas,
/// excluding external-call and calldata overhead so the numbers isolate the verification
/// logic itself. Run under different EVM versions to see precompile repricing effects:
/// `forge test --match-contract SchnorrVerifierGasTest -vv` (paris, repo default)
/// `FOUNDRY_PROFILE=prague ...` (pre-Fusaka mainnet)
/// `FOUNDRY_PROFILE=osaka ...` (post-Fusaka mainnet, EIP-7883 modexp repricing)
contract SchnorrVerifierGasHarness {
    function measureVerify(
        uint256 publicKeyX_,
        uint8 publicKeyYParity_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_
    ) external view returns (uint256 gasUsed_, bool isVerified_) {
        uint256 gasBefore_ = gasleft();
        bool result_ = SchnorrVerifierLib.verify(
            publicKeyX_,
            publicKeyYParity_,
            signatureScalar_,
            messageHash_,
            nonceX_
        );
        gasUsed_ = gasBefore_ - gasleft();
        isVerified_ = result_;
    }

    function measureVerifyWithNonceY(
        uint256 publicKeyX_,
        uint8 publicKeyYParity_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_,
        uint256 nonceY_
    ) external view returns (uint256 gasUsed_, bool isVerified_) {
        uint256 gasBefore_ = gasleft();
        bool result_ = SchnorrVerifierLib.verifyWithNonceY(
            publicKeyX_,
            publicKeyYParity_,
            signatureScalar_,
            messageHash_,
            nonceX_,
            nonceY_
        );
        gasUsed_ = gasBefore_ - gasleft();
        isVerified_ = result_;
    }
}

contract SchnorrVerifierGasTest is Test {
    uint256 internal constant SECP256K1_FIELD_PRIME =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant SECP256K1_SQRT_EXPONENT =
        0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C;

    // Official BIP340 test vector #3.
    uint256 internal constant VECTOR_3_PUBLIC_KEY_X =
        0x25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517;
    bytes32 internal constant VECTOR_3_MESSAGE_HASH =
        hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    uint256 internal constant VECTOR_3_NONCE_X =
        0x7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC;
    uint256 internal constant VECTOR_3_SIGNATURE_SCALAR =
        0x97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3;

    SchnorrVerifierGasHarness internal gasHarness;

    function setUp() public {
        gasHarness = new SchnorrVerifierGasHarness();
    }

    function testGasReportBothVerifierPaths() public {
        (uint256 modexpPathGas_, bool modexpPathVerified_) = gasHarness.measureVerify(
            VECTOR_3_PUBLIC_KEY_X,
            0,
            VECTOR_3_SIGNATURE_SCALAR,
            VECTOR_3_MESSAGE_HASH,
            VECTOR_3_NONCE_X
        );
        assertTrue(modexpPathVerified_);

        (uint256 witnessPathGas_, bool witnessPathVerified_) = gasHarness.measureVerifyWithNonceY(
            VECTOR_3_PUBLIC_KEY_X,
            0,
            VECTOR_3_SIGNATURE_SCALAR,
            VECTOR_3_MESSAGE_HASH,
            VECTOR_3_NONCE_X,
            _liftXToEvenY(VECTOR_3_NONCE_X)
        );
        assertTrue(witnessPathVerified_);

        emit log_named_uint("verify (modexp lift) execution gas", modexpPathGas_);
        emit log_named_uint("verifyWithNonceY (witness) execution gas", witnessPathGas_);
        emit log_named_uint("execution gas saved", modexpPathGas_ - witnessPathGas_);

        assertLt(witnessPathGas_, modexpPathGas_);
    }

    /// @dev Test-side witness generator (see production callers: any off-chain secp256k1 library).
    function _liftXToEvenY(uint256 pointX_) internal view returns (uint256 liftedEvenY_) {
        uint256 curveEquationValue_ = addmod(
            mulmod(
                mulmod(pointX_, pointX_, SECP256K1_FIELD_PRIME),
                pointX_,
                SECP256K1_FIELD_PRIME
            ),
            7,
            SECP256K1_FIELD_PRIME
        );

        (bool callSucceeded_, bytes memory output_) = address(0x05).staticcall(
            abi.encode(
                uint256(32),
                uint256(32),
                uint256(32),
                curveEquationValue_,
                SECP256K1_SQRT_EXPONENT,
                SECP256K1_FIELD_PRIME
            )
        );
        require(callSucceeded_ && output_.length == 32, "modexp failed");

        uint256 candidateY_ = abi.decode(output_, (uint256));
        require(
            mulmod(candidateY_, candidateY_, SECP256K1_FIELD_PRIME) == curveEquationValue_,
            "not on curve"
        );

        return (candidateY_ & 1) == 0 ? candidateY_ : SECP256K1_FIELD_PRIME - candidateY_;
    }
}
