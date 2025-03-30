// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import {WalletFactory} from "../contracts/WalletFactory.sol";

abstract contract WalletFactoryUpgrader is Script {
    // Replace this with your actual proxy address.
    address proxyAddress;

    function updateParams() internal virtual;

    function run() external {
        updateParams();
        vm.startBroadcast();

        // Deploy the new WalletFactory implementation
        WalletFactory newImplementation = new WalletFactory();
        console.log("New WalletFactory implementation deployed at:", address(newImplementation));

        // Get the proxy contract
        WalletFactory proxy = WalletFactory(proxyAddress);

        // Upgrade the implementation
        proxy.upgradeToAndCall(address(newImplementation), "");
        console.log("Proxy upgraded to new implementation at:", address(newImplementation));

        vm.stopBroadcast();
    }
}

// Contract for upgrading WalletFactory on Testnet
contract UpgradeWalletFactoryTestnet is WalletFactoryUpgrader {
    function updateParams() internal override {
        proxyAddress = 0x6aEEf85D78242eeaf8D0c71a730806dA26D7aCB1;
    }
}
