// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {GasStation} from "./GasStation.sol";
import {CREATE3} from "./utils/CREATE3.sol";
import {ISignerRegistry} from "./interfaces/ISignerRegistry.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

contract GasStationFactory is Initializable, UUPSUpgradeable {
    address public admin;
    address public relayer;
    address public signerRegistry;

    // Beacon holding the GasStation logic
    address public gasStationBeacon;

    // Mapping from clientId → deployed proxy
    mapping(bytes32 => address) public gasStations;

    event GasStationCreated(bytes32 indexed clientId, address gasStationAddress);
    event AdminChanged(address oldAdmin, address newAdmin);
    event RelayerChanged(address oldRelayer, address newRelayer);

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

    function initialize(address _admin, address _relayer, address _signerRegistry, address _initialGasStationImpl)
        external
        initializer
    {
        require(_admin != address(0), "Invalid admin");
        require(_relayer != address(0), "Invalid relayer");
        require(_signerRegistry != address(0), "Invalid registry");
        require(_initialGasStationImpl != address(0), "Invalid impl");

        __UUPSUpgradeable_init();

        admin = _admin;
        relayer = _relayer;
        signerRegistry = _signerRegistry;

        // Deploy beacon, admin controls upgrades
        UpgradeableBeacon beacon = new UpgradeableBeacon(_initialGasStationImpl, _admin);

        gasStationBeacon = address(beacon);
    }

    /// @notice Deploys a BeaconProxy via CREATE3, initializing with `clientId`.
    function createGasStation(bytes32 clientId) external onlySigner(clientId) returns (address proxyAddr) {
        require(gasStations[clientId] == address(0), "Already exists");
        bytes32 salt = keccak256(abi.encodePacked(clientId));

        // BeaconProxy constructor args: (beacon, initData)
        bytes memory initData = abi.encodeWithSelector(
            GasStation.initialize.selector,
            signerRegistry,
            admin,
            relayer
        );
        bytes memory beaconProxyCode =
            abi.encodePacked(type(BeaconProxy).creationCode, abi.encode(gasStationBeacon, initData));

        proxyAddr = CREATE3.deploy(salt, beaconProxyCode, 0);
        gasStations[clientId] = proxyAddr;
        emit GasStationCreated(clientId, proxyAddr);
    }

    /// @notice Compute address without deploying
    function computeAddress(bytes32 clientId) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(clientId));
        return CREATE3.getDeployed(salt);
    }

    /// @notice Upgrade implementation behind all proxies
    function upgradeGasStationImplementation(address newImpl) external onlyAdmin {
        UpgradeableBeacon(gasStationBeacon).upgradeTo(newImpl);
    }

    function setAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Invalid");
        admin = newAdmin;
        emit AdminChanged(admin, newAdmin);
    }

    function setRelayer(address newRelayer) external onlyAdmin {
        require(newRelayer != address(0), "Invalid");
        relayer = newRelayer;
        emit RelayerChanged(relayer, newRelayer);
    }

    function _authorizeUpgrade(address) internal override onlyAdmin {}
}
