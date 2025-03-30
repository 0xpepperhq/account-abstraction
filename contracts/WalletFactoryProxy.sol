// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "./WalletFactory.sol";

/// @title WalletFactoryProxy
/// @notice Proxy contract for WalletFactory implementation
/// @dev This proxy uses the UUPS upgradeable pattern
contract WalletFactoryProxy is ERC1967Proxy {
    /// @notice Constructor to deploy the proxy
    /// @param implementation The address of the implementation contract
    /// @param _data The initialization data for the implementation
    constructor(address implementation, bytes memory _data) ERC1967Proxy(implementation, _data) {}
}
