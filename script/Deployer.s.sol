// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";

import "../contracts/ContractRegistry.sol";
import "../contracts/GasStation.sol";
import "../contracts/SignerRegistry.sol";
import "../contracts/Wallet.sol";
import "../contracts/WalletFactory.sol";

contract Deployer is Script {
    function run() external {
        vm.startBroadcast();

        address admin = 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722;
        address relayer = 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722;

        // Deploy SignerRegistry
        SignerRegistry signerRegistry = new SignerRegistry(admin);
        console.log("SignerRegistry deployed at:", address(signerRegistry));

        // Deploy GasStation
        GasStation gasStation = new GasStation(address(signerRegistry), admin, relayer);
        console.log("GasStation deployed at:", address(gasStation));

        // Deploy ContractRegistry
        ContractRegistry contractRegistry = new ContractRegistry(address(signerRegistry));
        console.log("ContractRegistry deployed at:", address(contractRegistry));

        // Deploy WalletFactory
        WalletFactory walletFactory = new WalletFactory(
            admin,
            relayer,
            address(contractRegistry),
            address(signerRegistry)
        );
        console.log("WalletFactory deployed at:", address(walletFactory));
    }
}
