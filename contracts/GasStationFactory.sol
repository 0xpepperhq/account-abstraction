// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {GasStation} from "./GasStation.sol";
import {ISignerRegistry} from "./interfaces/ISignerRegistry.sol";
import {CREATE3} from "./utils/CREATE3.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract GasStationFactory is Initializable, UUPSUpgradeable {
    address public admin;
    address public relayer;
    address public signerRegistry;

    mapping(bytes32 => address) public gasStations;

    event GasStationCreated(bytes32 indexed clientId, address gasStationAddress);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event RelayerChanged(address indexed oldRelayer, address indexed newRelayer);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    modifier onlySigner(bytes32 clientId) {
        require(ISignerRegistry(signerRegistry).getSigner(clientId) == msg.sender, "Not authorized");
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _admin, address _relayer, address _signerRegistry) public initializer {
        require(_admin != address(0), "Invalid admin address");
        require(_relayer != address(0), "Invalid relayer address");
        require(_signerRegistry != address(0), "Invalid signer registry address");

        __UUPSUpgradeable_init();

        admin = _admin;
        relayer = _relayer;
        signerRegistry = _signerRegistry;
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

    /// @notice Creates a new GasStation contract using CREATE2
    /// @param clientId The client ID
    /// @return gasStationAddress The address of the created GasStation contract
    function createGasStation(bytes32 clientId) external onlySigner(clientId) returns (address gasStationAddress) {
        bytes32 salt = keccak256(abi.encodePacked(clientId));
        bytes memory bytecode =
            abi.encodePacked(type(GasStation).creationCode, abi.encode(signerRegistry, admin, relayer));

        gasStationAddress = CREATE3.deploy(salt, bytecode, 0);
        emit GasStationCreated(clientId, gasStationAddress);
        gasStations[clientId] = gasStationAddress;
    }

    /// @notice Computes the address of the GasStation for the given clientId
    /// @param clientId The client ID
    /// @return gasStationAddress The address of the GasStation contract
    function computeAddress(bytes32 clientId) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(clientId));
        return CREATE3.getDeployed(salt);
    }

    /// @notice Required override for UUPS upgradeable pattern
    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}
}
