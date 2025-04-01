// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import {ContractRegistry} from "../contracts/ContractRegistry.sol";

abstract contract ContractRegistryUpgrader is Script {
    // Replace this with your actual proxy address.
    address proxyAddress;

    function updateParams() internal virtual;

    function run() external {
        updateParams();
        vm.startBroadcast();

        // Deploy the new ContractRegistry implementation
        ContractRegistry newImplementation = new ContractRegistry();
        console.log("New ContractRegistry implementation deployed at:", address(newImplementation));

        // Get the proxy contract
        ContractRegistry proxy = ContractRegistry(proxyAddress);

        // Upgrade the implementation
        proxy.upgradeToAndCall(address(newImplementation), "");
        console.log("Proxy upgraded to new implementation at:", address(newImplementation));

        vm.stopBroadcast();
    }
}

// Contract for upgrading ContractRegistry on Testnet
contract UpgradeContractRegistry is ContractRegistryUpgrader {
    function updateParams() internal override {
        proxyAddress = 0xAeB1080f28f266d4Cf3E869d9501bC165d707B79;
    }
}
