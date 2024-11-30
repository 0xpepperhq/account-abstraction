// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

interface IContractRegistry {
    function isContractAllowed(bytes32 _clientId, address _contract) external view returns (bool);
}
