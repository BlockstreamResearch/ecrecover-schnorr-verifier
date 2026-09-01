// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {SchnorrVerifierLib} from "./libs/crypto/SchnorrVerifierLib.sol";

contract SchnorrVerifier {
    /// @notice External wrapper around the library verifier.
    /// @dev `publicKeyX_` is the canonical even-y x-only key and must be in `[1, n-1]`.
    /// `signatureScalar_` follows BIP340's range `[0, n-1]`. The exact 32 bytes in
    /// `messageHash_` are signed. This contract neither hashes nor domain-separates them.
    /// The integrating application must authorize the final post-tweak key and bind its
    /// tweak/signing context and replay policy. Security remains conditional on RPAC.
    function verify(
        uint256 publicKeyX_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_
    ) external view returns (bool isVerified_) {
        // Delegate verification to assembly-heavy library implementation.
        return SchnorrVerifierLib.verify(publicKeyX_, signatureScalar_, messageHash_, nonceX_);
    }

    /// @notice Verifies using a caller-supplied even nonce y-coordinate.
    /// @dev The witness is range-checked and proven to be the even secp256k1 point for `nonceX_`.
    /// The same final-key, message-domain, context, replay, and RPAC obligations as `verify` apply.
    function verifyWithNonceY(
        uint256 publicKeyX_,
        uint256 signatureScalar_,
        bytes32 messageHash_,
        uint256 nonceX_,
        uint256 nonceY_
    ) external view returns (bool isVerified_) {
        return
            SchnorrVerifierLib.verifyWithNonceY(
                publicKeyX_,
                signatureScalar_,
                messageHash_,
                nonceX_,
                nonceY_
            );
    }
}
