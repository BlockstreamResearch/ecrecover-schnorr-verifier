// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";

import {SchnorrVerifier} from "../contracts/SchnorrVerifier.sol";

contract SchnorrVerifierFoundryTest is Test {
    uint256 internal constant SECP256K1_FIELD_PRIME =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant SECP256K1_SCALAR_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant SECP256K1_SQRT_EXPONENT =
        0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C;
    bytes32 internal constant BIP340_CHALLENGE_TAG_HASH =
        hex"7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c";

    address internal constant ECRECOVER_PRECOMPILE = address(0x01);
    address internal constant SHA256_PRECOMPILE = address(0x02);
    address internal constant MODEXP_PRECOMPILE = address(0x05);

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
    uint256 internal constant ODD_BRANCH_PUBLIC_KEY_X =
        0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9;
    uint256 internal constant ODD_BRANCH_SIGNATURE_SCALAR =
        0x9F811EEBB9EA784653B2B32C92059D4850781EBF42363E02972E9D62CACC95E9;
    uint256 internal constant ODD_BRANCH_NONCE_X =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant ODD_BRANCH_NONCE_Y =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    struct VerifierInput {
        uint256 publicKeyX;
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

    function testRejectsOddKeyBranchSignatureAcceptedBeforeParityHardening() public view {
        VerifierInput memory input_ = VerifierInput({
            publicKeyX: ODD_BRANCH_PUBLIC_KEY_X,
            signatureScalar: ODD_BRANCH_SIGNATURE_SCALAR,
            messageHash: bytes32(0),
            nonceX: ODD_BRANCH_NONCE_X
        });

        assertFalse(_verify(input_));
        assertFalse(_verifyWithNonceY(input_, ODD_BRANCH_NONCE_Y));
    }

    function testFuzzRejectsOutOfRangeInputs(
        bytes32 messageHash_,
        uint256 secretKeyScalar_,
        bytes32 auxRand_
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
    }

    function testZeroSignatureScalarFollowsBip340Range() public {
        bytes32 messageHash_ = keccak256("synthetic s=0 branch");
        uint256 challengeScalar_ = SECP256K1_SCALAR_ORDER - 1;
        _mockChallenge(ODD_BRANCH_NONCE_X, ODD_BRANCH_NONCE_X, messageHash_, challengeScalar_);

        VerifierInput memory input_ = VerifierInput({
            publicKeyX: ODD_BRANCH_NONCE_X,
            signatureScalar: 0,
            messageHash: messageHash_,
            nonceX: ODD_BRANCH_NONCE_X
        });

        // With e = n - 1, the transformed recovery computes Q = P = R even when s = 0.
        // This synthetic challenge is injected because finding such a SHA-256 preimage is infeasible.
        assertTrue(_verify(input_));
        assertTrue(_verifyWithNonceY(input_, ODD_BRANCH_NONCE_Y));
    }

    function testRejectsZeroChallengeBeforeRecovery() public {
        bytes32 messageHash_ = keccak256("synthetic e=0 branch");
        _mockChallenge(ODD_BRANCH_NONCE_X, ODD_BRANCH_NONCE_X, messageHash_, 0);

        VerifierInput memory input_ = VerifierInput({
            publicKeyX: ODD_BRANCH_NONCE_X,
            signatureScalar: 0,
            messageHash: messageHash_,
            nonceX: ODD_BRANCH_NONCE_X
        });
        bytes memory recoveryInput_ = _recoveryInput(input_, 0);
        address noncePointAddress_ = _pointAddress(ODD_BRANCH_NONCE_X, ODD_BRANCH_NONCE_Y);

        // If recovery were reached, this mock would make the address comparison succeed.
        // Explicit e=0 rejection therefore distinguishes this behavior from incidental
        // rejection by the precompile's zero ECDSA-scalar rule.
        vm.mockCall(ECRECOVER_PRECOMPILE, recoveryInput_, abi.encode(noncePointAddress_));

        assertFalse(_verify(input_));
        assertFalse(_verifyWithNonceY(input_, ODD_BRANCH_NONCE_Y));
    }

    function testRejectsZeroRecoveryResult() public {
        bytes32 messageHash_ = keccak256("zero recovery result");
        uint256 challengeScalar_ = SECP256K1_SCALAR_ORDER - 1;
        _mockChallenge(ODD_BRANCH_NONCE_X, ODD_BRANCH_NONCE_X, messageHash_, challengeScalar_);

        VerifierInput memory input_ = VerifierInput({
            publicKeyX: ODD_BRANCH_NONCE_X,
            signatureScalar: 0,
            messageHash: messageHash_,
            nonceX: ODD_BRANCH_NONCE_X
        });
        vm.mockCall(
            ECRECOVER_PRECOMPILE,
            _recoveryInput(input_, challengeScalar_),
            abi.encode(address(0))
        );

        assertFalse(_verify(input_));
        assertFalse(_verifyWithNonceY(input_, ODD_BRANCH_NONCE_Y));
    }

    function testRejectsFailedRecoveryCall() public {
        bytes32 messageHash_ = keccak256("failed recovery call");
        uint256 challengeScalar_ = SECP256K1_SCALAR_ORDER - 1;
        _mockChallenge(ODD_BRANCH_NONCE_X, ODD_BRANCH_NONCE_X, messageHash_, challengeScalar_);

        VerifierInput memory input_ = VerifierInput({
            publicKeyX: ODD_BRANCH_NONCE_X,
            signatureScalar: 0,
            messageHash: messageHash_,
            nonceX: ODD_BRANCH_NONCE_X
        });
        vm.mockCallRevert(
            ECRECOVER_PRECOMPILE,
            _recoveryInput(input_, challengeScalar_),
            "synthetic failure"
        );

        assertFalse(_verify(input_));
        assertFalse(_verifyWithNonceY(input_, ODD_BRANCH_NONCE_Y));
    }

    function testFuzzVerifyDoesNotRevertOnArbitraryInput(
        uint256 publicKeyX_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_
    ) public view {
        // A randomly generated tuple may be a valid signature. This test only asserts
        // the intended property: arbitrary typed inputs do not revert.
        verifier.verify(publicKeyX_, signatureScalar_, messageHash_, nonceX_);
    }

    function testRustHelperVector3VerifiesWithNonceYWitness() public {
        VerifierInput memory input_ = _sign(
            VECTOR_3_MESSAGE_HASH,
            uint256(VECTOR_3_SECRET_KEY),
            VECTOR_3_AUX_RAND
        );
        (bool isOnCurve_, uint256 nonceY_) = _liftXToEvenY(input_.nonceX);

        assertTrue(isOnCurve_);
        assertTrue(_verifyWithNonceY(input_, nonceY_));
    }

    function testFuzzVerifyWithNonceYAcceptsRustGeneratedSignatures(
        bytes32 messageHash_,
        uint256 secretKeyScalar_,
        bytes32 auxRand_
    ) public {
        VerifierInput memory input_ = _signBounded(messageHash_, secretKeyScalar_, auxRand_);
        (bool isOnCurve_, uint256 nonceY_) = _liftXToEvenY(input_.nonceX);

        assertTrue(isOnCurve_);
        assertTrue(_verifyWithNonceY(input_, nonceY_));
    }

    function testFuzzWitnessPathMatchesVerify(
        uint256 publicKeyX_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_
    ) public view {
        (bool isOnCurve_, uint256 nonceY_) = _liftXToEvenY(nonceX_);

        bool expected_ = verifier.verify(publicKeyX_, signatureScalar_, messageHash_, nonceX_);
        bool actual_ = verifier.verifyWithNonceY(
            publicKeyX_,
            signatureScalar_,
            messageHash_,
            nonceX_,
            isOnCurve_ ? nonceY_ : 0
        );

        assertEq(actual_, expected_);
    }

    function testVerifyWithNonceYRejectsInvalidWitnesses() public {
        VerifierInput memory input_ = _sign(
            VECTOR_3_MESSAGE_HASH,
            uint256(VECTOR_3_SECRET_KEY),
            VECTOR_3_AUX_RAND
        );
        (bool isOnCurve_, uint256 nonceY_) = _liftXToEvenY(input_.nonceX);
        assertTrue(isOnCurve_);

        assertFalse(_verifyWithNonceY(input_, SECP256K1_FIELD_PRIME - nonceY_));
        assertFalse(_verifyWithNonceY(input_, nonceY_ + 2));
        assertFalse(_verifyWithNonceY(input_, SECP256K1_FIELD_PRIME));
        assertFalse(_verifyWithNonceY(input_, type(uint256).max));
    }

    function testFuzzVerifyWithNonceYDoesNotRevertOnArbitraryInput(
        uint256 publicKeyX_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_,
        uint256 nonceY_
    ) public view {
        // A randomly generated tuple may be a valid signature. This test only asserts
        // the intended property: arbitrary typed inputs do not revert.
        verifier.verifyWithNonceY(publicKeyX_, signatureScalar_, messageHash_, nonceX_, nonceY_);
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
            uint256 signatureScalar_,
            bytes32 ffiMessageHash_,
            uint256 nonceX_
        ) = abi.decode(vm.ffi(command_), (uint256, uint256, bytes32, uint256));

        input_ = VerifierInput({
            publicKeyX: publicKeyX_,
            signatureScalar: signatureScalar_,
            messageHash: ffiMessageHash_,
            nonceX: nonceX_
        });
    }

    function _verify(VerifierInput memory input_) internal view returns (bool) {
        return
            verifier.verify(
                input_.publicKeyX,
                input_.signatureScalar,
                input_.messageHash,
                input_.nonceX
            );
    }

    function _verifyWithNonceY(
        VerifierInput memory input_,
        uint256 nonceY_
    ) internal view returns (bool) {
        return
            verifier.verifyWithNonceY(
                input_.publicKeyX,
                input_.signatureScalar,
                input_.messageHash,
                input_.nonceX,
                nonceY_
            );
    }

    function _mockChallenge(
        uint256 nonceX_,
        uint256 publicKeyX_,
        bytes32 messageHash_,
        uint256 challengeScalar_
    ) internal {
        bytes memory challengeInput_ = abi.encode(
            BIP340_CHALLENGE_TAG_HASH,
            BIP340_CHALLENGE_TAG_HASH,
            bytes32(nonceX_),
            bytes32(publicKeyX_),
            messageHash_
        );
        vm.mockCall(SHA256_PRECOMPILE, challengeInput_, abi.encode(challengeScalar_));
    }

    function _recoveryInput(
        VerifierInput memory input_,
        uint256 challengeScalar_
    ) internal pure returns (bytes memory recoveryInput_) {
        uint256 negatedChallengeScalar_ = challengeScalar_ == 0
            ? 0
            : SECP256K1_SCALAR_ORDER - challengeScalar_;
        return
            abi.encode(
                bytes32(
                    SECP256K1_SCALAR_ORDER -
                        mulmod(input_.publicKeyX, input_.signatureScalar, SECP256K1_SCALAR_ORDER)
                ),
                uint256(27),
                bytes32(input_.publicKeyX),
                bytes32(mulmod(negatedChallengeScalar_, input_.publicKeyX, SECP256K1_SCALAR_ORDER))
            );
    }

    function _pointAddress(
        uint256 pointX_,
        uint256 pointY_
    ) internal pure returns (address pointAddress_) {
        return address(uint160(uint256(keccak256(abi.encode(pointX_, pointY_)))));
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
