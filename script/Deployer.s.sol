// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "../contracts/WalletFactoryProxy.sol";
import "../contracts/GasStationFactoryProxy.sol";

import "../contracts/ContractRegistry.sol";
import "../contracts/SignerRegistry.sol";
import "../contracts/Wallet.sol";
import "../contracts/WalletFactory.sol";
import "../contracts/SignatureHelper.sol";
import "../contracts/GasStationFactory.sol";

abstract contract Deployer is Script {
    address admin;
    address relayer;
    address signerRegistry;
    address contractRegistry;

    function updateParams() internal virtual;

    function run() external {
        updateParams();

        vm.startBroadcast();

        // Deploy WalletFactory implementation
        WalletFactory walletFactoryImpl = new WalletFactory();
        console.log("WalletFactory implementation deployed at:", address(walletFactoryImpl));

        // Deploy WalletFactory proxy
        bytes memory walletFactoryData = abi.encodeWithSelector(
            WalletFactory.initialize.selector, admin, relayer, address(contractRegistry), address(signerRegistry)
        );
        WalletFactoryProxy walletFactoryProxy = new WalletFactoryProxy(address(walletFactoryImpl), walletFactoryData);
        console.log("WalletFactory proxy deployed at:", address(walletFactoryProxy));

        SignatureHelper signatureHelper = new SignatureHelper();
        console.log("SignatureHelper deployed at:", address(signatureHelper));

        // Deploy GasStationFactory implementation
        GasStationFactory gasStationFactoryImpl = new GasStationFactory();
        console.log("GasStationFactory implementation deployed at:", address(gasStationFactoryImpl));

        // Deploy GasStationFactory proxy
        bytes memory gasStationFactoryData =
            abi.encodeWithSelector(GasStationFactory.initialize.selector, admin, relayer, address(signerRegistry));
        GasStationFactoryProxy gasStationFactoryProxy =
            new GasStationFactoryProxy(address(gasStationFactoryImpl), gasStationFactoryData);
        console.log("GasStationFactory proxy deployed at:", address(gasStationFactoryProxy));
    }
}

contract DeployerTest is Deployer {
    function updateParams() internal override {
        admin = 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722;
        relayer = 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722;
        signerRegistry = 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722;
        contractRegistry = 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722;
    }
}
