// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import {SignerRegistry} from "../contracts/SignerRegistry.sol";

abstract contract SignerRegistryUpgrader is Script {
    // Replace this with your actual proxy address.
    address proxyAddress;

    function updateParams() internal virtual;

    function run() external {
        updateParams();
        vm.startBroadcast();

        // Deploy the new SignerRegistry implementation
        SignerRegistry newImplementation = new SignerRegistry();
        console.log("New SignerRegistry implementation deployed at:", address(newImplementation));

        // Get the proxy contract
        SignerRegistry proxy = SignerRegistry(proxyAddress);

        // Upgrade the implementation
        proxy.upgradeToAndCall(address(newImplementation), "");
        console.log("Proxy upgraded to new implementation at:", address(newImplementation));

        vm.stopBroadcast();
    }
}

// Contract for upgrading SignerRegistry on Testnet
contract UpgradeSignerRegistryTestnet is SignerRegistryUpgrader {
    function updateParams() internal override {
        proxyAddress = 0x191231425D7daF919F3cEdB7B36B08805bd01B40;
    }
}
