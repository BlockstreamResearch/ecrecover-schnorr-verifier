// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";

import {SchnorrVerifier} from "../contracts/SchnorrVerifier.sol";

contract SchnorrVerifierFoundryTest is Test {
    uint256 internal constant SECP256K1_FIELD_PRIME =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant SECP256K1_SCALAR_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    bytes32 internal constant VECTOR_3_SECRET_KEY =
        hex"0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710";
    bytes32 internal constant VECTOR_3_AUX_RAND =
        hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    bytes32 internal constant VECTOR_3_MESSAGE_HASH =
        hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    uint256 internal constant VECTOR_3_PUBLIC_KEY_X =
        0x25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517;
    uint256 internal constant VECTOR_3_NONCE_X =
        0x7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC;
    uint256 internal constant VECTOR_3_SIGNATURE_SCALAR =
        0x97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3;

    struct VerifierInput {
        uint256 publicKeyX;
        uint8 publicKeyYParity;
        uint256 signatureScalar;
        bytes32 messageHash;
        uint256 nonceX;
    }

    SchnorrVerifier internal verifier;
    string internal signerBinaryPath;

    function setUp() public {
        verifier = new SchnorrVerifier();
        signerBinaryPath = string.concat(
            vm.projectRoot(),
            "/tools/schnorr-ffi/target/release/schnorr-ffi"
        );
    }

    function testRustHelperSmokeMatchesBip340Vector3() public {
        VerifierInput memory input_ = _sign(
            VECTOR_3_MESSAGE_HASH,
            uint256(VECTOR_3_SECRET_KEY),
            VECTOR_3_AUX_RAND
        );

        assertEq(input_.publicKeyX, VECTOR_3_PUBLIC_KEY_X);
        assertEq(input_.publicKeyYParity, 0);
        assertEq(input_.signatureScalar, VECTOR_3_SIGNATURE_SCALAR);
        assertEq(input_.messageHash, VECTOR_3_MESSAGE_HASH);
        assertEq(input_.nonceX, VECTOR_3_NONCE_X);
        assertTrue(_verify(input_));
    }

    function testFuzzVerifyAcceptsRustGeneratedSignatures(
        bytes32 messageHash_,
        uint256 secretKeyScalar_,
        bytes32 auxRand_
    ) public {
        VerifierInput memory input_ = _signBounded(messageHash_, secretKeyScalar_, auxRand_);

        assertEq(input_.publicKeyYParity, 0);
        assertEq(input_.messageHash, messageHash_);
        assertTrue(_verify(input_));
    }

    function testFuzzRejectsTamperedMessageHash(
        bytes32 messageHash_,
        uint256 secretKeyScalar_,
        bytes32 auxRand_,
        bytes32 tamperedMessageHash_
    ) public {
        VerifierInput memory input_ = _signBounded(messageHash_, secretKeyScalar_, auxRand_);
        vm.assume(tamperedMessageHash_ != input_.messageHash);

        input_.messageHash = tamperedMessageHash_;

        assertFalse(_verify(input_));
    }

    function testFuzzRejectsTamperedSignatureScalar(
        bytes32 messageHash_,
        uint256 secretKeyScalar_,
        bytes32 auxRand_,
        uint256 scalarDelta_
    ) public {
        VerifierInput memory input_ = _signBounded(messageHash_, secretKeyScalar_, auxRand_);
        uint256 boundedScalarDelta_ = bound(scalarDelta_, 1, SECP256K1_SCALAR_ORDER - 1);

        // Any additive shift of `s` within Zn yields a different scalar and must be rejected.
        input_.signatureScalar = addmod(
            input_.signatureScalar,
            boundedScalarDelta_,
            SECP256K1_SCALAR_ORDER
        );

        assertFalse(_verify(input_));
    }

    function testFuzzRejectsTamperedNonceX(
        bytes32 messageHash_,
        uint256 secretKeyScalar_,
        bytes32 auxRand_,
        uint256 tamperedNonceX_
    ) public {
        VerifierInput memory input_ = _signBounded(messageHash_, secretKeyScalar_, auxRand_);
        uint256 boundedTamperedNonceX_ = bound(tamperedNonceX_, 1, SECP256K1_FIELD_PRIME - 1);
        vm.assume(boundedTamperedNonceX_ != input_.nonceX);

        // Covers both off-curve x values (rejected by lifting) and on-curve
        // values (rejected by the final address comparison).
        input_.nonceX = boundedTamperedNonceX_;

        assertFalse(_verify(input_));
    }

    function testFuzzRejectsTamperedPublicKeyX(
        bytes32 messageHash_,
        uint256 secretKeyScalar_,
        bytes32 auxRand_,
        uint256 tamperedPublicKeyX_
    ) public {
        VerifierInput memory input_ = _signBounded(messageHash_, secretKeyScalar_, auxRand_);
        uint256 boundedTamperedPublicKeyX_ = bound(
            tamperedPublicKeyX_,
            1,
            SECP256K1_SCALAR_ORDER - 1
        );
        vm.assume(boundedTamperedPublicKeyX_ != input_.publicKeyX);

        // A signature must not verify against any key other than the signer's.
        input_.publicKeyX = boundedTamperedPublicKeyX_;

        assertFalse(_verify(input_));
    }

    function testFuzzRejectsFlippedParity(
        bytes32 messageHash_,
        uint256 secretKeyScalar_,
        bytes32 auxRand_
    ) public {
        VerifierInput memory input_ = _signBounded(messageHash_, secretKeyScalar_, auxRand_);

        // BIP340 keys are even-y; verifying against the odd-y branch targets -P
        // and must fail.
        input_.publicKeyYParity = 1;

        assertFalse(_verify(input_));
    }

    function testFuzzRejectsOutOfRangeInputs(
        bytes32 messageHash_,
        uint256 secretKeyScalar_,
        bytes32 auxRand_,
        uint8 parity_
    ) public {
        VerifierInput memory valid_ = _signBounded(messageHash_, secretKeyScalar_, auxRand_);

        // Each mutation pushes exactly one otherwise-valid input out of its
        // documented domain; all must be rejected without reverting.
        VerifierInput memory input_ = valid_;
        input_.publicKeyX = 0;
        assertFalse(_verify(input_));
        input_.publicKeyX = SECP256K1_SCALAR_ORDER;
        assertFalse(_verify(input_));
        input_.publicKeyX = type(uint256).max;
        assertFalse(_verify(input_));

        input_ = valid_;
        input_.signatureScalar = 0;
        assertFalse(_verify(input_));
        input_.signatureScalar = SECP256K1_SCALAR_ORDER;
        assertFalse(_verify(input_));
        input_.signatureScalar = type(uint256).max;
        assertFalse(_verify(input_));

        input_ = valid_;
        input_.nonceX = 0;
        assertFalse(_verify(input_));
        input_.nonceX = SECP256K1_FIELD_PRIME;
        assertFalse(_verify(input_));
        input_.nonceX = type(uint256).max;
        assertFalse(_verify(input_));

        input_ = valid_;
        input_.publicKeyYParity = uint8(bound(parity_, 2, type(uint8).max));
        assertFalse(_verify(input_));
    }

    function testFuzzRejectsArbitraryInputWithoutReverting(
        uint256 publicKeyX_,
        uint8 publicKeyYParity_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_
    ) public view {
        // Unstructured input must never verify (a hit here would be a forgery)
        // and must never revert.
        assertFalse(
            verifier.verify(
                publicKeyX_,
                publicKeyYParity_,
                signatureScalar_,
                messageHash_,
                nonceX_
            )
        );
    }

    /// @dev Signs with a secret key bounded into `[1, n-1]` and skips runs whose
    /// public key x does not fit the ECDSA `r` slot, mirroring the accept-path fuzz test.
    function _signBounded(
        bytes32 messageHash_,
        uint256 secretKeyScalar_,
        bytes32 auxRand_
    ) internal returns (VerifierInput memory input_) {
        uint256 boundedSecretKeyScalar_ = bound(secretKeyScalar_, 1, SECP256K1_SCALAR_ORDER - 1);
        input_ = _sign(messageHash_, boundedSecretKeyScalar_, auxRand_);

        vm.assume(input_.publicKeyX < SECP256K1_SCALAR_ORDER);
    }

    function _sign(
        bytes32 messageHash_,
        uint256 secretKeyScalar_,
        bytes32 auxRand_
    ) internal returns (VerifierInput memory input_) {
        string[] memory command_ = new string[](5);
        command_[0] = signerBinaryPath;
        command_[1] = "sign";
        command_[2] = vm.toString(messageHash_);
        command_[3] = vm.toString(bytes32(secretKeyScalar_));
        command_[4] = vm.toString(auxRand_);

        (
            uint256 publicKeyX_,
            uint8 publicKeyYParity_,
            uint256 signatureScalar_,
            bytes32 ffiMessageHash_,
            uint256 nonceX_
        ) = abi.decode(vm.ffi(command_), (uint256, uint8, uint256, bytes32, uint256));

        input_ = VerifierInput({
            publicKeyX: publicKeyX_,
            publicKeyYParity: publicKeyYParity_,
            signatureScalar: signatureScalar_,
            messageHash: ffiMessageHash_,
            nonceX: nonceX_
        });
    }

    function _verify(VerifierInput memory input_) internal view returns (bool) {
        return
            verifier.verify(
                input_.publicKeyX,
                input_.publicKeyYParity,
                input_.signatureScalar,
                input_.messageHash,
                input_.nonceX
            );
    }
}
