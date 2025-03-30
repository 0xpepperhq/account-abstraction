// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "./ContractRegistry.sol";

/// @title ContractRegistryProxy
/// @notice Proxy contract for ContractRegistry implementation
/// @dev This proxy uses the UUPS upgradeable pattern
contract ContractRegistryProxy is ERC1967Proxy {
    /// @notice Constructor to deploy the proxy
    /// @param implementation The address of the implementation contract
    /// @param _data The initialization data for the implementation
    constructor(address implementation, bytes memory _data) ERC1967Proxy(implementation, _data) {}
}

