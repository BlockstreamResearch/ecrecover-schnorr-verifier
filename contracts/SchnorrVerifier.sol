// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {SchnorrVerifierLib} from "./libs/crypto/SchnorrVerifierLib.sol";

contract SchnorrVerifier {
    /// @notice External wrapper around the library verifier.
    /// @dev Keeps ABI simple while all cryptographic logic lives in `SchnorrVerifierLib`.
    function verify(
        uint256 publicKeyX,
        uint8 publicKeyYParity,
        uint256 signatureScalar,
        bytes32 messageHash,
        uint256 nonceX
    ) external view returns (bool isVerified_) {
        // Delegate verification to assembly-heavy library implementation.
        return
            SchnorrVerifierLib.verify(
                publicKeyX,
                publicKeyYParity,
                signatureScalar,
                messageHash,
                nonceX
            );
    }
}
