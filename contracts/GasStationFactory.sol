// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {GasStation} from "./GasStation.sol";
import {ISignerRegistry} from "./interfaces/ISignerRegistry.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

contract GasStationFactory {
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

    constructor(
        address _admin,
        address _relayer,
        address _signerRegistry
    ) {
        require(_admin != address(0), "Invalid admin address");
        require(_relayer != address(0), "Invalid relayer address");
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
        bytes memory bytecode = abi.encodePacked(
            type(GasStation).creationCode,
            abi.encode(signerRegistry, admin, relayer)
        );

        gasStationAddress = Create2.deploy(0, salt, bytecode);
        emit GasStationCreated(clientId, gasStationAddress);
        gasStations[clientId] = gasStationAddress;
    }

    /// @notice Computes the address of the GasStation for the given clientId
    /// @param clientId The client ID
    /// @return gasStationAddress The address of the GasStation contract
    function computeAddress(bytes32 clientId) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(clientId));
        bytes memory bytecode = abi.encodePacked(
            type(GasStation).creationCode,
            abi.encode(signerRegistry, admin, relayer)
        );

        return Create2.computeAddress(salt, keccak256(bytecode));
    }
}
