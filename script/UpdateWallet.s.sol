// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import {WalletFactory} from "../contracts/WalletFactory.sol";
import {Wallet} from "../contracts/Wallet.sol";

abstract contract UpgradeWallet is Script {
    // Replace this with your actual proxy address.
    address proxyAddress;

    function updateParams() internal virtual;

    function run() external {
        updateParams();
        vm.startBroadcast();

        // Get the proxy contract
        WalletFactory walletFactory = WalletFactory(proxyAddress);

        // Deploy the new Event implementation
        Wallet newImplementation = new Wallet();

        // Upgrade the implementation
        walletFactory.upgradeWalletImplementation(address(newImplementation));

        vm.stopBroadcast();
    }
}

contract UpdateWallet is UpgradeWallet {
    function updateParams() internal override {
        proxyAddress = 0xDEcd7d5f3CFC7EF6c53B95946c8630A1cad8b407;
    }
}
