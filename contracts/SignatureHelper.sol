// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "./Wallet.sol";

contract SignatureHelper {
    /// @notice Helper function to generate EIP-712 signature
    function generateDigestForExecuteAction(
        address to,
        uint256 value,
        bytes memory data,
        uint256 _nonce,
        Types.ReimburseGas memory gasParams,
        address walletAddress
    ) public view returns (bytes32 digest) {
        Wallet wallet = Wallet(payable(walletAddress));

        // Compute the message hash
        bytes32 gasStructHash = keccak256(
            abi.encode(
                wallet.REIMBURSE_GAS_TYPEHASH(),
                gasParams.gasPrice,
                gasParams.gasLimit,
                gasParams.reimburse,
                gasParams.reimburseInNative,
                gasParams.tokenRate,
                gasParams.token
            )
        );

        bytes32 structHash =
            keccak256(abi.encode(wallet.EXECUTE_ACTION_TYPEHASH(), to, value, keccak256(data), _nonce, gasStructHash));

        digest = keccak256(abi.encodePacked("\x19\x01", wallet.DOMAIN_SEPARATOR(), structHash));
    }
}
