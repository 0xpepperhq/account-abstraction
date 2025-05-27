// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import {GasStationFactory} from "../contracts/GasStationFactory.sol";
import {GasStation} from "../contracts/GasStation.sol";

abstract contract UpgradeGasStation is Script {
    // Replace this with your actual proxy address.
    address proxyAddress;

    function updateParams() internal virtual;

    function run() external {
        updateParams();
        vm.startBroadcast();

        // Get the proxy contract
        GasStationFactory gasStationFactory = GasStationFactory(proxyAddress);

        // Deploy the new Event implementation
        GasStation newImplementation = new GasStation();

        // Upgrade the implementation
        gasStationFactory.upgradeGasStationImplementation(address(newImplementation));

        vm.stopBroadcast();
    }
}

contract UpdateGasStation is UpgradeGasStation {
    function updateParams() internal override {
        proxyAddress = 0x3adaCA28f07Cd28Cb40e0e5442b0Eb0b0AB33710;
    }
}
