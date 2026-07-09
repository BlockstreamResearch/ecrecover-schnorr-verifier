// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";

import {SchnorrVerifierHarness} from "../certora/harness/SchnorrVerifierHarness.sol";

/// @notice Differential fuzz between the optimized library verifier and the assembly-free
/// reference implementation used as the Certora equivalence oracle
/// (`certora/specs/SchnorrVerifier.spec`). Validates the oracle empirically so a
/// prover-reported divergence can be trusted to point at the assembly, not at the reference.
contract SchnorrVerifierReferenceTest is Test {
    uint256 internal constant SECP256K1_SCALAR_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

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
        uint8 publicKeyYParity_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_
    ) public view {
        assertEq(
            harness.verifyOptimized(
                publicKeyX_,
                publicKeyYParity_,
                signatureScalar_,
                messageHash_,
                nonceX_
            ),
            harness.verifyReference(
                publicKeyX_,
                publicKeyYParity_,
                signatureScalar_,
                messageHash_,
                nonceX_
            )
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
            uint8 publicKeyYParity_,
            uint256 signatureScalar_,
            bytes32 ffiMessageHash_,
            uint256 nonceX_
        ) = abi.decode(vm.ffi(command_), (uint256, uint8, uint256, bytes32, uint256));

        vm.assume(publicKeyX_ < SECP256K1_SCALAR_ORDER);

        // The reference must accept honest signatures and agree with the optimized verifier.
        assertTrue(
            harness.verifyReference(
                publicKeyX_,
                publicKeyYParity_,
                signatureScalar_,
                ffiMessageHash_,
                nonceX_
            )
        );
        assertTrue(
            harness.verifyOptimized(
                publicKeyX_,
                publicKeyYParity_,
                signatureScalar_,
                ffiMessageHash_,
                nonceX_
            )
        );
    }
}
