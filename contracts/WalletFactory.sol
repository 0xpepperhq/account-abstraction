// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {Wallet} from "./Wallet.sol";
import {GasStation} from "./GasStation.sol";
import {ISignerRegistry} from "./interfaces/ISignerRegistry.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

// CREATE3 deployer contract
contract ProxyDeployer {
    event Deployed(address addr);
    
    function deploy(bytes memory bytecode, bytes32 salt) external returns (address addr) {
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(extcodesize(addr)) {
                revert(0, 0)
            }
        }
        emit Deployed(addr);
    }
}

contract WalletFactory {
    address public admin;
    address public relayer;
    address public contractRegistry;
    address public signerRegistry;
    ProxyDeployer public deployer;

    // Mapping from off-chain client ids and user IDs to wallet addresses
    mapping(bytes32 => mapping(bytes32 => address)) public wallets;

    // Events
    event WalletCreated(bytes32 indexed userId, bytes32 indexed clientId, address walletAddress);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event RelayerChanged(address indexed oldRelayer, address indexed newRelayer);
    event ContractRegistryChanged(address indexed oldRegistry, address indexed newRegistry);
    event GasStationCreated(bytes32 indexed clientId, address gasStationAddress);
    event DeployerCreated(address deployerAddress);

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
        
        // Deploy the ProxyDeployer contract
        deployer = new ProxyDeployer();
        emit DeployerCreated(address(deployer));
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
            
            // First use the deployer to deploy a proxy contract
            address proxy = deployProxy(salt);
            
            // Then use the proxy to deploy the actual wallet
            bytes memory walletBytecode = getUserWalletCreationCode(clientId);
            walletAddress = deployThroughProxy(proxy, walletBytecode);
            
            // Map the userId to the wallet address
            wallets[clientId][userId] = walletAddress;

            emit WalletCreated(userId, clientId, walletAddress);
        }
    }
    
    /// @notice Deploys a proxy contract using CREATE2
    /// @param salt The salt for deterministic address
    /// @return proxyAddress The address of the deployed proxy
    function deployProxy(bytes32 salt) internal returns (address proxyAddress) {
        // This is the bytecode of a minimal proxy contract that just delegates calls
        bytes memory proxyCode = hex"3d602d80600a3d3981f3363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3";
        
        // Deploy the proxy
        proxyAddress = address(deployer.deploy(proxyCode, salt));
        return proxyAddress;
    }
    
    /// @notice Uses the deployed proxy to deploy the actual wallet contract
    /// @param proxy The address of the proxy
    /// @param walletBytecode The bytecode of the wallet to deploy
    /// @return walletAddress The address of the deployed wallet
    function deployThroughProxy(address proxy, bytes memory walletBytecode) internal returns (address walletAddress) {
        // The address is deterministic based on the deployed proxy
        walletAddress = address(uint160(uint(keccak256(abi.encodePacked(
            bytes1(0xd6), // prefix for CREATE
            bytes1(0x94), // prefix for addresses
            proxy,
            bytes1(0x01)  // nonce 1
        )))));
        
        // Execute deployment through the proxy
        (bool success, ) = proxy.call(walletBytecode);
        require(success, "Wallet deployment failed");
        
        return walletAddress;
    }

    /// @notice Computes the address of the UserWallet for the given userId and clientId across any chain
    /// @param userId The off-chain user ID
    /// @param clientId The client ID
    /// @return The computed wallet address
    function computeWalletAddress(
        bytes32 userId,
        bytes32 clientId
    ) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(userId, clientId));
        
        // First compute the proxy address
        bytes memory proxyCode = hex"3d602d80600a3d3981f3363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3";
        bytes32 proxyCodeHash = keccak256(proxyCode);
        address proxy = Create2.computeAddress(salt, proxyCodeHash, address(deployer));
        
        // Then compute the wallet address based on the proxy address
        return address(uint160(uint(keccak256(abi.encodePacked(
            bytes1(0xd6), // prefix for CREATE
            bytes1(0x94), // prefix for addresses
            proxy,
            bytes1(0x01)  // nonce 1
        )))));
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
}
