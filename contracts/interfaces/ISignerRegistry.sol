// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

interface ISignerRegistry {
    function getSigner(bytes32 clientId) external view returns (address signer);
    function registerSigner(bytes32 clientId, address signer) external;
}
