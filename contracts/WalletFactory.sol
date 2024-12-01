// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {Wallet} from "./Wallet.sol";
import {GasStation} from "./GasStation.sol";
import {ISignerRegistry} from "./interfaces/ISignerRegistry.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

contract WalletFactory {
    address public admin;
    address public relayer;
    address public contractRegistry;
    address public signerRegistry;

    // Mapping from off-chain client ids and user IDs to wallet addresses
    mapping(bytes32 => mapping(bytes32 => address)) public wallets;
    mapping(bytes32 => address) public gasStations;

    // Events
    event WalletCreated(bytes32 indexed userId, bytes32 indexed clientId, address walletAddress);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event RelayerChanged(address indexed oldRelayer, address indexed newRelayer);
    event ContractRegistryChanged(address indexed oldRegistry, address indexed newRegistry);
    event GasStationCreated(bytes32 indexed clientId, address gasStationAddress);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    modifier onlySigner(bytes32 clientId) {
        require(ISignerRegistry(signerRegistry).getSigner(clientId) == msg.sender, "Not authorized");
        _;
    }

    constructor(
        address _admin,
        address _relayer,
        address _contractRegistry,
        address _signerRegistry
    ) {
        require(_admin != address(0), "Invalid admin address");
        require(_relayer != address(0), "Invalid relayer address");
        require(_contractRegistry != address(0), "Invalid contract registry address");
        admin = _admin;
        relayer = _relayer;
        contractRegistry = _contractRegistry;
        signerRegistry = _signerRegistry;
    }

    /// @notice Creates a new Wallet using CREATE2 and maps it to the off-chain user ID
    /// @param userId The off-chain user ID
    /// @param clientId The client ID
    /// @return walletAddress The address of the created wallet
    function createWallet(bytes32 userId, bytes32 clientId) external onlyAdmin returns (address walletAddress) {
        require(wallets[clientId][userId] == address(0), "Wallet already exists for this user");

        // Compute the salt from userId and clientId
        bytes32 salt = keccak256(abi.encodePacked(userId, clientId));

        // Compute the initialization code
        bytes memory bytecode = getUserWalletCreationCode(clientId);

        // Deploy the contract using CREATE2
        walletAddress = Create2.deploy(0, salt, bytecode);

        // Map the userId to the wallet address
        wallets[clientId][userId] = walletAddress;

        emit WalletCreated(userId, clientId, walletAddress);
    }

    /// @notice Computes the address of the UserWallet for the given userId and clientId
    /// @param userId The off-chain user ID
    /// @param clientId The client ID
    /// @return The computed wallet address
    function computeWalletAddress(
        bytes32 userId,
        bytes32 clientId
    ) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(userId, clientId));
        bytes memory bytecode = getUserWalletCreationCode(clientId);
        bytes32 codeHash = keccak256(bytecode);
        return Create2.computeAddress(salt, codeHash, address(this));
    }

    /// @notice Generates the initialization code for the UserWallet
    /// @param clientId The client ID for the UserWallet
    /// @return The initialization bytecode of the UserWallet
    function getUserWalletCreationCode(bytes32 clientId) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(Wallet).creationCode,
            abi.encode(clientId, relayer, contractRegistry, signerRegistry)
        );
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

    /// @notice Creates a new GasStation contract using CREATE2
    /// @param clientId The client ID
    /// @return gasStationAddress The address of the created GasStation contract
    function createGasStation(bytes32 clientId) external onlySigner(clientId) returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(clientId));
        bytes memory bytecode = abi.encodePacked(
            type(GasStation).creationCode,
            abi.encode(signerRegistry, admin, relayer)
        );

        address gasStationAddress = Create2.deploy(0, salt, bytecode);
        emit GasStationCreated(clientId, gasStationAddress);
        gasStations[clientId] = gasStationAddress;
        return gasStationAddress;
    }
}
