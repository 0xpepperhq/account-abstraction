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

        address signerRegistry = 0xC955532A0C0ffc9b9ac7aFFAcEA3832b2dBb85AD;
        address contractRegistry = 0x485e770deDfeAc4aF621beC0a5e9366AfC7a6D37;
        address signer = 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722;
        bytes32 clientId = 0xb33237270006a2cb6b24935fc83a916d366f4c2a5b9ea8b91ea3b191606c11cf;

        // Deploy SignerRegistry
        SignerRegistry(signerRegistry).registerSigner(clientId, signer);

        // Deploy ContractRegistry
        address lotteryFactory = 0x0b2cF496c65496b85CfEF8BFee438CfE8e49a56b;
        address eventFactory = 0x870B48dF207E11302805A5D33FcE47B780329029;
        address freeToPlayToken = 0x9Ff6a0DC28dfc56858BDC677E77858E00BDF7D44;
        address marketMaket = 0xb58bd982F522528a55e5132d5b07C7bcFE44427b;
        address outcomeToken = 0x021837743e581E101189f6638db192A6dDaE85FB;

        ContractRegistry(contractRegistry).setAllowedContract(clientId, lotteryFactory, true);
        ContractRegistry(contractRegistry).setAllowedContract(clientId, eventFactory, true);
        ContractRegistry(contractRegistry).setAllowedContract(clientId, freeToPlayToken, true);
        ContractRegistry(contractRegistry).setAllowedContract(clientId, marketMaket, true);
        ContractRegistry(contractRegistry).setAllowedContract(clientId, outcomeToken, true);
    }
}
