// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";

import "../contracts/ContractRegistry.sol";
import "../contracts/SignerRegistry.sol";
import "../contracts/Wallet.sol";
import "../contracts/WalletFactory.sol";
import "../contracts/SignatureHelper.sol";
import "../contracts/GasStationFactory.sol";

contract Setup is Script {
    function run() external {
        vm.startBroadcast();

        // address signerRegistry = 0x5a684137fddb5dFF6e2276906BDbf0510F022FBc;
        address contractRegistry = 0x75C4A34B13a891679241A34bEfA3c5a83bFE032a;
        // address signer = 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722;
        bytes32 clientId = 0xb33237270006a2cb6b24935fc83a916d366f4c2a5b9ea8b91ea3b191606c11cf;

        // Deploy SignerRegistry
        // SignerRegistry(signerRegistry).registerSigner(clientId, signer);

        // Deploy ContractRegistry
        // address lotteryFactory = 0x7Cf08228EC01191c2693B9539D02B37DACCC3f24;
        address eventFactory = 0x827a01E3dEBdE2997C10d20b15a17b2615CBFFeF;
        // address freeToPlayToken = 0x9Ff6a0DC28dfc56858BDC677E77858E00BDF7D44;

        // ContractRegistry(contractRegistry).setAllowedContract(clientId, lotteryFactory, true);
        ContractRegistry(contractRegistry).setAllowedContract(clientId, eventFactory, true);
        // ContractRegistry(contractRegistry).setAllowedContract(clientId, freeToPlayToken, true);
    }
}
