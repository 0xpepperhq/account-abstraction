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

        address signerRegistry = 0x95310aaC029CD393A227492628FD825DFE3a6d5D;
        address contractRegistry = 0x7b33B1263901a8cDE3b986b046218f7E7132C479;
        address signer = 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722;
        bytes32 clientId = 0xb33237270006a2cb6b24935fc83a916d366f4c2a5b9ea8b91ea3b191606c11cf;

        SignerRegistry(signerRegistry).registerSigner(clientId, signer);

        address lotteryFactory = 0x406907a0bb5163E38522724653c00B3cCD84aEbC;
        address eventFactory = 0xD020E48dB59a046b496f4B1A8c6d45C2180666CF;
        address freeToPlayToken = 0x9Ff6a0DC28dfc56858BDC677E77858E00BDF7D44;
        address marketMaket = 0xb012368792A26aba67a5DB3880d3B2643596E7F4;
        address outcomeToken = 0xe40f8fDB01Ced6DcCf49Bb5c6D5f7168b6806aEd;

        SignerRegistry(signerRegistry).registerDelegateSigner(clientId, lotteryFactory);
        SignerRegistry(signerRegistry).registerDelegateSigner(clientId, eventFactory);

        ContractRegistry(contractRegistry).setAllowedContract(clientId, lotteryFactory, true);
        ContractRegistry(contractRegistry).setAllowedContract(clientId, eventFactory, true);
        ContractRegistry(contractRegistry).setAllowedContract(clientId, freeToPlayToken, true);
        ContractRegistry(contractRegistry).setAllowedContract(clientId, marketMaket, true);
        ContractRegistry(contractRegistry).setAllowedContract(clientId, outcomeToken, true);
    }
}
