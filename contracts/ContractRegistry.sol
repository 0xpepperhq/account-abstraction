// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ISignerRegistry} from "./interfaces/ISignerRegistry.sol";

contract ContractRegistry is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    // Signer Registry
    ISignerRegistry public signerRegistry;
    address public admin;
    // Mapping of allowed contracts
    mapping(bytes32 => mapping(address => bool)) private clientAllowedContracts;

    // Events
    event ContractAllowed(address indexed _contract, bool _allowed);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    modifier onlySignerDelegate(bytes32 _clientId) {
        require(signerRegistry.isDelegateSigner(_clientId, msg.sender), "Not authorized Delegate");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized Admin");
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _admin, address _signerRegistry) public initializer {
        require(_signerRegistry != address(0), "Invalid signerRegistry address");

        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        signerRegistry = ISignerRegistry(_signerRegistry);
        admin = _admin;
    }

    /// @notice Allows the admin to set allowed contracts
    /// @param _contract The contract address to allow or disallow
    /// @param _allowed Boolean indicating whether the contract is allowed
    function setAllowedContract(bytes32 _clientId, address _contract, bool _allowed)
        external
        onlySignerDelegate(_clientId)
        nonReentrant
    {
        clientAllowedContracts[_clientId][_contract] = _allowed;
        emit ContractAllowed(_contract, _allowed);
    }

    /// @notice Checks if a contract is allowed
    /// @param _contract The contract address to check
    /// @return True if the contract is allowed, false otherwise
    function isContractAllowed(bytes32 _clientId, address _contract) external view returns (bool) {
        return clientAllowedContracts[_clientId][_contract];
    }

    /// @notice Allows the admin to change the admin address
    /// @param _newAdmin The new admin address
    function setAdmin(address _newAdmin) external onlyAdmin {
        require(_newAdmin != address(0), "Invalid admin address");
        emit AdminChanged(admin, _newAdmin);
        admin = _newAdmin;
    }

    /// @custom:oz-upgrades-allow-protected-functions
    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}
}
