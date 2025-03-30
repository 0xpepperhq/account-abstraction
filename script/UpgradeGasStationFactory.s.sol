// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import {GasStationFactory} from "../contracts/GasStationFactory.sol";

abstract contract GasStationFactoryUpgrader is Script {
    // Replace this with your actual proxy address.
    address proxyAddress;

    function updateParams() internal virtual;

    function run() external {
        updateParams();
        vm.startBroadcast();

        // Deploy the new GasStationFactory implementation
        GasStationFactory newImplementation = new GasStationFactory();
        console.log("New GasStationFactory implementation deployed at:", address(newImplementation));

        // Get the proxy contract
        GasStationFactory proxy = GasStationFactory(proxyAddress);

        // Upgrade the implementation
        proxy.upgradeToAndCall(address(newImplementation), "");
        console.log("Proxy upgraded to new implementation at:", address(newImplementation));

        vm.stopBroadcast();
    }
}

// Contract for upgrading GasStationFactory on Testnet
contract UpgradeGasStationFactoryTestnet is GasStationFactoryUpgrader {
    function updateParams() internal override {
        proxyAddress = 0x191231425D7daF919F3cEdB7B36B08805bd01B40;
    }
}
