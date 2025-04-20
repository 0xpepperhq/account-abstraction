// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {Wallet} from "./Wallet.sol";
import {CREATE3} from "./utils/CREATE3.sol";
import {ISignerRegistry} from "./interfaces/ISignerRegistry.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract WalletFactory is Initializable, UUPSUpgradeable {
    address public admin;
    address public relayer;
    address public contractRegistry;
    address public signerRegistry;
    bytes public walletInitCode;

    // Mapping from off-chain client ids and user IDs to wallet addresses
    mapping(bytes32 => mapping(bytes32 => address)) public wallets;

    // Events
    event WalletCreated(bytes32 indexed userId, bytes32 indexed clientId, address walletAddress);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event RelayerChanged(address indexed oldRelayer, address indexed newRelayer);
    event ContractRegistryChanged(address indexed oldRegistry, address indexed newRegistry);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized Admin");
        _;
    }

    modifier onlySigner(bytes32 clientId) {
        require(ISignerRegistry(signerRegistry).getSigner(clientId) == msg.sender, "Not authorized Signer");
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _admin, address _relayer, address _contractRegistry, address _signerRegistry)
        public
        initializer
    {
        require(_admin != address(0), "Invalid admin address");
        require(_relayer != address(0), "Invalid relayer address");
        require(_contractRegistry != address(0), "Invalid contract registry address");
        require(_signerRegistry != address(0), "Invalid signer registry address");

        __UUPSUpgradeable_init();

        admin = _admin;
        relayer = _relayer;
        contractRegistry = _contractRegistry;
        signerRegistry = _signerRegistry;
        walletInitCode = type(Wallet).creationCode;
    }

    /// @notice Creates a new Wallet using CREATE3 pattern and maps it to the off-chain user ID
    /// @param userId The off-chain user ID
    /// @param clientId The client ID
    /// @return walletAddress The address of the created wallet
    function createWallet(bytes32 userId, bytes32 clientId) external onlyAdmin returns (address walletAddress) {
        require(userId.length > 0, "Invalid userId");
        require(clientId.length > 0, "Invalid clientId");

        walletAddress = wallets[clientId][userId];

        if (walletAddress == address(0)) {
            // Generate a stable salt from userId and clientId - same across all chains
            bytes32 salt = keccak256(abi.encodePacked(userId, clientId));

            // Get the wallet creation code
            bytes memory walletBytecode = getUserWalletCreationCode(clientId);

            // Use CREATE3 library to deploy the wallet
            walletAddress = CREATE3.deploy(salt, walletBytecode, 0);

            // Map the userId to the wallet address
            wallets[clientId][userId] = walletAddress;

            emit WalletCreated(userId, clientId, walletAddress);
        }
    }

    /// @notice Computes the address of the UserWallet for the given userId and clientId across any chain
    /// @param userId The off-chain user ID
    /// @param clientId The client ID
    /// @return The computed wallet address
    function computeWalletAddress(bytes32 userId, bytes32 clientId) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(userId, clientId));
        return CREATE3.getDeployed(salt);
    }

    /// @notice Generates the initialization code for the UserWallet
    /// @param clientId The client ID for the UserWallet
    /// @return The initialization bytecode of the UserWallet
    function getUserWalletCreationCode(bytes32 clientId) internal view returns (bytes memory) {
        return abi.encodePacked(walletInitCode, abi.encode(clientId, relayer, contractRegistry, signerRegistry));
    }

    /// @notice Allows the admin to update the wallet initialization code
    /// @param _walletInitCode The new wallet initialization code
    /// @dev This function is only callable by the admin
    function updateWalletCreationCode(bytes memory _walletInitCode) external onlyAdmin {
        walletInitCode = _walletInitCode;
    }

    /// @notice Allows the admin to change the admin address
    /// @param _newAdmin The new admin address
    function setAdmin(address _newAdmin) external onlyAdmin {
        require(_newAdmin != address(0), "Invalid admin address");
        emit AdminChanged(admin, _newAdmin);
        admin = _newAdmin;
    }

    /// @notice Allows the admin to change the relayer address
    /// @param _newRelayer The new relayer address
    function setRelayer(address _newRelayer) external onlyAdmin {
        require(_newRelayer != address(0), "Invalid relayer address");
        emit RelayerChanged(relayer, _newRelayer);
        relayer = _newRelayer;
    }

    /// @notice Allows the admin to change the ContractRegistry address
    /// @param _newRegistry The new ContractRegistry address
    function setContractRegistry(address _newRegistry) external onlyAdmin {
        require(_newRegistry != address(0), "Invalid contract registry address");
        emit ContractRegistryChanged(contractRegistry, _newRegistry);
        contractRegistry = _newRegistry;
    }

    /// @notice Retrieves the wallet address for a given userId
    /// @param clientId The off-chain user ID
    /// @param userId The off-chain user ID
    /// @return The address of the user's wallet
    function getWallet(bytes32 clientId, bytes32 userId) external view returns (address) {
        return wallets[clientId][userId];
    }

    /// @notice Required override for UUPS upgradeable pattern
    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}
}
