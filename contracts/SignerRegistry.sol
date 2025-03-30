// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ISignerRegistry} from "./interfaces/ISignerRegistry.sol";

contract SignerRegistry is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, ISignerRegistry {
    address public admin;

    // Mapping of allowed contracts
    mapping(address => bool) private blocklistSigners;
    mapping(bytes32 => address) private signers;
    mapping(address => mapping(address => bool)) private delegateSigners;

    // Events
    event SignerRegistered(bytes32 indexed clientId, address signer);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized Admin");
        _;
    }

    modifier onlySigner(bytes32 clientId) {
        address signer = signers[clientId];
        require(signer != address(0), "Signer not found");
        require(!blocklistSigners[signer], "Signer is blocked");
        require(signer == msg.sender, "Not authorized Signer");
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _admin) public initializer {
        require(_admin != address(0), "Invalid admin address");

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        admin = _admin;
    }

    /// @notice Allows the admin register signers
    /// @param clientId The client ID
    /// @param signer The contract address to allow or disallow
    function registerSigner(bytes32 clientId, address signer) external onlyAdmin nonReentrant {
        signers[clientId] = signer;
        delegateSigners[signer][signer] = true;
        emit SignerRegistered(clientId, signer);
    }

    /// @notice Allows the admin to delegate signers
    /// @param clientId The client ID
    /// @param delegate The delegate address
    function registerDelegateSigner(bytes32 clientId, address delegate) external onlySigner(clientId) nonReentrant {
        address signer = signers[clientId];
        delegateSigners[signer][delegate] = true;
    }

    /// @notice Get the signer for a client ID
    /// @param clientId The client ID
    /// @return signer The signer address
    function getSigner(bytes32 clientId) external view returns (address signer) {
        signer = signers[clientId];
        require(signer != address(0), "Signer not found");
        require(!blocklistSigners[signer], "Signer is blocked");
    }

    /// @notice Allows the admin to delegate signers
    /// @param clientId The client ID
    /// @param delegate The delegate address
    function isDelegateSigner(bytes32 clientId, address delegate) external view returns (bool) {
        address signer = signers[clientId];
        return delegateSigners[signer][delegate];
    }

    /// @notice Allows the admin to block signers
    /// @param signer The signer address to block
    function blockSigner(address signer) external onlyAdmin nonReentrant {
        blocklistSigners[signer] = true;
    }

    /// @notice Allows the admin to change the admin address
    /// @param _newAdmin The new admin address
    function setAdmin(address _newAdmin) external onlyAdmin nonReentrant {
        require(_newAdmin != address(0), "Invalid admin address");
        emit AdminChanged(admin, _newAdmin);
        admin = _newAdmin;
    }

    /// @custom:oz-upgrades-allow-protected-functions
    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}
}
