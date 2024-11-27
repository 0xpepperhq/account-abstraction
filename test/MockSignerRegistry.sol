// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

/// @title MockSignerRegistry
/// @notice A mock implementation of the ISignerRegistry interface for testing purposes.
contract MockSignerRegistry {
    // Mapping from clientId to signer address
    mapping(bytes32 => address) private signers;

    /// @notice Registers a signer for a given clientId
    /// @param clientId The client ID
    /// @param signer The signer address
    function registerSigner(bytes32 clientId, address signer) external {
        signers[clientId] = signer;
    }

    /// @notice Retrieves the signer for a given clientId
    /// @param clientId The client ID
    /// @return signer The signer address
    function getSigner(bytes32 clientId) external view returns (address signer) {
        signer = signers[clientId];
    }
}
