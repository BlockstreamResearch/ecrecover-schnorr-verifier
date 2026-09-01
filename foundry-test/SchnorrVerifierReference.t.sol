// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";

import {SchnorrVerifierHarness} from "../certora/harness/SchnorrVerifierHarness.sol";

/// @notice Differential fuzz between the optimized library verifier and the assembly-free
/// reference implementation used as the Certora equivalence oracle
/// (`certora/specs/SchnorrVerifier.spec`). Validates the oracle empirically so a
/// prover-reported divergence can be trusted to point at the assembly, not at the reference.
contract SchnorrVerifierReferenceTest is Test {
    uint256 internal constant SECP256K1_FIELD_PRIME =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant SECP256K1_SCALAR_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant SECP256K1_SQRT_EXPONENT =
        0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C;

    address internal constant MODEXP_PRECOMPILE = address(0x05);

    SchnorrVerifierHarness internal harness;
    string internal signerBinaryPath;

    function setUp() public {
        harness = new SchnorrVerifierHarness();
        signerBinaryPath = string.concat(
            vm.projectRoot(),
            "/tools/schnorr-ffi/target/release/schnorr-ffi"
        );
    }

    function testFuzzReferenceMatchesOptimizedOnArbitraryInput(
        uint256 publicKeyX_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_
    ) public view {
        assertEq(
            harness.verifyOptimized(publicKeyX_, signatureScalar_, messageHash_, nonceX_),
            harness.verifyReference(publicKeyX_, signatureScalar_, messageHash_, nonceX_)
        );
    }

    function testFuzzWitnessReferenceMatchesOptimizedOnArbitraryInput(
        uint256 publicKeyX_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_,
        uint256 nonceY_
    ) public view {
        assertEq(
            harness.verifyWithNonceYOptimized(
                publicKeyX_,
                signatureScalar_,
                messageHash_,
                nonceX_,
                nonceY_
            ),
            harness.verifyWithNonceYReference(
                publicKeyX_,
                signatureScalar_,
                messageHash_,
                nonceX_,
                nonceY_
            )
        );
    }

    function testFuzzZeroSignatureScalarReferenceMatchesOptimized(
        uint256 publicKeyX_,
        bytes32 messageHash_,
        uint256 nonceX_
    ) public view {
        assertEq(
            harness.verifyOptimized(publicKeyX_, 0, messageHash_, nonceX_),
            harness.verifyReference(publicKeyX_, 0, messageHash_, nonceX_)
        );
    }

    function testFuzzZeroSignatureScalarWitnessReferenceMatchesOptimized(
        uint256 publicKeyX_,
        bytes32 messageHash_,
        uint256 nonceX_,
        uint256 nonceY_
    ) public view {
        assertEq(
            harness.verifyWithNonceYOptimized(publicKeyX_, 0, messageHash_, nonceX_, nonceY_),
            harness.verifyWithNonceYReference(publicKeyX_, 0, messageHash_, nonceX_, nonceY_)
        );
    }

    function testFuzzReferenceAcceptsRustGeneratedSignatures(
        bytes32 messageHash_,
        uint256 secretKeyScalar_,
        bytes32 auxRand_
    ) public {
        uint256 boundedSecretKeyScalar_ = bound(secretKeyScalar_, 1, SECP256K1_SCALAR_ORDER - 1);

        string[] memory command_ = new string[](5);
        command_[0] = signerBinaryPath;
        command_[1] = "sign";
        command_[2] = vm.toString(messageHash_);
        command_[3] = vm.toString(bytes32(boundedSecretKeyScalar_));
        command_[4] = vm.toString(auxRand_);

        (
            uint256 publicKeyX_,
            uint256 signatureScalar_,
            bytes32 ffiMessageHash_,
            uint256 nonceX_
        ) = abi.decode(vm.ffi(command_), (uint256, uint256, bytes32, uint256));

        vm.assume(publicKeyX_ < SECP256K1_SCALAR_ORDER);
        (bool isOnCurve_, uint256 nonceY_) = _liftXToEvenY(nonceX_);
        assertTrue(isOnCurve_);

        // The reference must accept honest signatures and agree with the optimized verifier.
        assertTrue(
            harness.verifyReference(publicKeyX_, signatureScalar_, ffiMessageHash_, nonceX_)
        );
        assertTrue(
            harness.verifyOptimized(publicKeyX_, signatureScalar_, ffiMessageHash_, nonceX_)
        );
        assertTrue(
            harness.verifyWithNonceYReference(
                publicKeyX_,
                signatureScalar_,
                ffiMessageHash_,
                nonceX_,
                nonceY_
            )
        );
        assertTrue(
            harness.verifyWithNonceYOptimized(
                publicKeyX_,
                signatureScalar_,
                ffiMessageHash_,
                nonceX_,
                nonceY_
            )
        );
    }

    function _liftXToEvenY(
        uint256 pointX_
    ) internal view returns (bool isOnCurve_, uint256 evenY_) {
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
