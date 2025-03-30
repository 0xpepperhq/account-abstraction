// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "../contracts/WalletFactoryProxy.sol";
import "../contracts/GasStationFactoryProxy.sol";

import "../contracts/ContractRegistry.sol";
import "../contracts/SignerRegistry.sol";
import "../contracts/Wallet.sol";
import "../contracts/WalletFactory.sol";
import "../contracts/GasStationFactory.sol";
import "../contracts/ContractRegistryProxy.sol";
import "../contracts/SignerRegistryProxy.sol";

abstract contract Deployer is Script {
    address admin;
    address relayer;

    function updateParams() internal virtual;

    function run() external {
        updateParams();

        vm.startBroadcast();

        // Deploy SignerRegistry implementation
        SignerRegistry signerRegistryImpl = new SignerRegistry();
        console.log("SignerRegistry implementation deployed at:", address(signerRegistryImpl));

        // Deploy SignerRegistry proxy
        bytes memory signerRegistryData = abi.encodeWithSelector(SignerRegistry.initialize.selector);
        SignerRegistryProxy signerRegistryProxy = new SignerRegistryProxy(address(signerRegistryImpl), signerRegistryData);
        console.log("SignerRegistry proxy deployed at:", address(signerRegistryProxy));

        // Deploy ContractRegistry implementation
        ContractRegistry contractRegistryImpl = new ContractRegistry();
        console.log("ContractRegistry implementation deployed at:", address(contractRegistryImpl));

        // Deploy ContractRegistry proxy
        bytes memory contractRegistryData = abi.encodeWithSelector(
            ContractRegistry.initialize.selector, admin, address(signerRegistryProxy)
        );
        ContractRegistryProxy contractRegistryProxy = new ContractRegistryProxy(address(contractRegistryImpl), contractRegistryData);
        console.log("ContractRegistry proxy deployed at:", address(contractRegistryProxy));

        // Deploy WalletFactory implementation
        WalletFactory walletFactoryImpl = new WalletFactory();
        console.log("WalletFactory implementation deployed at:", address(walletFactoryImpl));

        // Deploy WalletFactory proxy
        bytes memory walletFactoryData = abi.encodeWithSelector(
            WalletFactory.initialize.selector, admin, relayer, address(contractRegistryProxy), address(signerRegistryProxy)
        );
        WalletFactoryProxy walletFactoryProxy = new WalletFactoryProxy(address(walletFactoryImpl), walletFactoryData);
        console.log("WalletFactory proxy deployed at:", address(walletFactoryProxy));

        // Deploy GasStationFactory implementation
        GasStationFactory gasStationFactoryImpl = new GasStationFactory();
        console.log("GasStationFactory implementation deployed at:", address(gasStationFactoryImpl));

        // Deploy GasStationFactory proxy
        bytes memory gasStationFactoryData =
            abi.encodeWithSelector(GasStationFactory.initialize.selector, admin, relayer, address(signerRegistryProxy));
        GasStationFactoryProxy gasStationFactoryProxy =
            new GasStationFactoryProxy(address(gasStationFactoryImpl), gasStationFactoryData);
        console.log("GasStationFactory proxy deployed at:", address(gasStationFactoryProxy));
    }
}

contract DeployerTest is Deployer {
    function updateParams() internal override {
        admin = 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722;
        relayer = 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722;
    }
}
