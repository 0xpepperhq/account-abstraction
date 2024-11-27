// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

/// @title Types Library
/// @notice Contains shared data structures
library Types {
    struct ReimburseGas {
        uint256 gasPrice;
        uint256 gasLimit;
        bool reimburse;
        bool reimburseInNative;
        uint256 tokenRate; // Tokens per wei (scaled by 1e18)
        address token;
    }
}
