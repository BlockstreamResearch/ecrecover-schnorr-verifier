// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {SchnorrVerifierLib} from "./libs/crypto/SchnorrVerifierLib.sol";

contract SchnorrVerifier {
    /// @notice External wrapper around the library verifier.
    /// @dev Keeps ABI simple while all cryptographic logic lives in `SchnorrVerifierLib`.
    function verify(
        uint256 publicKeyX_,
        uint8 publicKeyYParity_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_
    ) external view returns (bool isVerified_) {
        // Delegate verification to assembly-heavy library implementation.
        return
            SchnorrVerifierLib.verify(
                publicKeyX_,
                publicKeyYParity_,
                signatureScalar_,
                messageHash_,
                nonceX_
            );
    }

    /// @notice External wrapper around the witness-based library verifier.
    /// @dev Skips the modexp square root by taking the nonce point y-coordinate as a
    /// caller-supplied witness; see `SchnorrVerifierLib.verifyWithNonceY`.
    function verifyWithNonceY(
        uint256 publicKeyX_,
        uint8 publicKeyYParity_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_,
        uint256 nonceY_
    ) external view returns (bool isVerified_) {
        // Delegate verification to assembly-heavy library implementation.
        return
            SchnorrVerifierLib.verifyWithNonceY(
                publicKeyX_,
                publicKeyYParity_,
                signatureScalar_,
                messageHash_,
                nonceX_,
                nonceY_
            );
    }
}
