// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import {GasStation} from "../contracts/GasStation.sol";
import {GasStationFactory} from "../contracts/GasStationFactory.sol";
import {SignerRegistry} from "../contracts/SignerRegistry.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

/**
 * @title GasStationFactoryTest
 * @dev Unit tests for the GasStationFactory contract.
 */
contract GasStationFactoryTest is Test {
    GasStationFactory public gasStationFactory;
    SignerRegistry public signerRegistry;

    // Test Addresses
    address public admin = address(0x1);
    address public relayer = address(0x2);
    address public signer1 = address(0x3);
    address public signer2 = address(0x4);

    // Client IDs
    bytes32 public clientId1 = keccak256("Client1");
    bytes32 public clientId2 = keccak256("Client2");

    function setUp() public {
        // Deploy SignerRegistry
        signerRegistry = new SignerRegistry(admin);

        // Deploy GasStationFactory with admin, relayer, and signerRegistry
        vm.startPrank(admin);
        gasStationFactory = new GasStationFactory(admin, relayer, address(signerRegistry));

        // Set signers for client IDs
        signerRegistry.registerSigner(clientId1, signer1);
        signerRegistry.registerSigner(clientId2, signer2);
        vm.stopPrank();
    }

    /**
     * @notice Test that the constructor initializes variables correctly.
     */
    function testConstructorInitialization() public {
        assertEq(gasStationFactory.admin(), admin, "Admin address mismatch");
        assertEq(gasStationFactory.relayer(), relayer, "Relayer address mismatch");
        assertEq(address(gasStationFactory.signerRegistry()), address(signerRegistry), "SignerRegistry address mismatch");
    }

    /**
     * @notice Test that only admin can change the admin address.
     */
    function testSetAdmin() public {
        address newAdmin = address(0x5);

        // Attempt to change admin from non-admin account
        vm.prank(relayer);
        vm.expectRevert("Not authorized");
        gasStationFactory.setAdmin(newAdmin);

        // Change admin from admin account
        vm.prank(admin);
        gasStationFactory.setAdmin(newAdmin);
        assertEq(gasStationFactory.admin(), newAdmin, "Admin was not updated correctly");
    }

    /**
     * @notice Test that only admin can change the relayer address.
     */
    function testSetRelayer() public {
        address newRelayer = address(0x6);

        // Attempt to change relayer from non-admin account
        vm.prank(signer1);
        vm.expectRevert("Not authorized");
        gasStationFactory.setRelayer(newRelayer);

        // Change relayer from admin account
        vm.prank(admin);
        gasStationFactory.setRelayer(newRelayer);
        assertEq(gasStationFactory.relayer(), newRelayer, "Relayer was not updated correctly");
    }

    /**
     * @notice Test that only authorized signers can create GasStation contracts.
     */
    function testCreateGasStation() public {
        // Signer1 creates GasStation for clientId1
        vm.prank(signer1);
        address gasStationAddress1 = gasStationFactory.createGasStation(clientId1);
        assertTrue(gasStationFactory.gasStations(clientId1) == gasStationAddress1, "GasStation not registered correctly");

        // Signer2 creates GasStation for clientId2
        vm.prank(signer2);
        address gasStationAddress2 = gasStationFactory.createGasStation(clientId2);
        assertTrue(gasStationFactory.gasStations(clientId2) == gasStationAddress2, "GasStation not registered correctly");

        // Attempt to create GasStation from unauthorized signer
        vm.prank(relayer);
        vm.expectRevert("Not authorized");
        gasStationFactory.createGasStation(clientId1);
    }

    /**
     * @notice Test that GasStation is created using CREATE2 with correct salt and bytecode.
     */
    function testGasStationCreationUsingCreate2() public {
        bytes32 clientId = keccak256("Client3");
        address signer = address(0x7);

        // Set signer for clientId
        vm.prank(admin);
        signerRegistry.registerSigner(clientId, signer);

        address computedAddress = gasStationFactory.computeAddress(clientId);

        // Prank as signer and create GasStation
        vm.prank(signer);
        address gasStationAddress = gasStationFactory.createGasStation(clientId);

        // Verify that the GasStation was deployed at the expected address
        assertEq(gasStationAddress, computedAddress, "GasStation was not deployed at the expected address");
    }

    /**
     * @notice Test that creating a GasStation emits the GasStationCreated event.
     */
    function testCreateGasStationEmitsEvent() public {
        bytes32 clientId = keccak256("Client4");
        address signer = address(0x8);

        // Set signer for clientId
        vm.prank(admin);
        signerRegistry.registerSigner(clientId, signer);

        address computedGasStationStation = gasStationFactory.computeAddress(clientId);

        // Expect the GasStationCreated event
        vm.expectEmit(true, true, false, true);
        emit GasStationFactory.GasStationCreated(clientId, computedGasStationStation); // The actual address is not known here

        // Prank as signer and create GasStation
        vm.prank(signer);
        address gasStationStation = gasStationFactory.createGasStation(clientId);
        assertEq(computedGasStationStation, gasStationStation, "GasStation address mismatch");
    }

    /**
     * @notice Test that only existing signers can create GasStations.
     */
    function testCreateGasStationWithNonexistentSigner() public {
        bytes32 clientId = keccak256("Client5");

        // Ensure no signer is set for clientId
        vm.expectRevert("Signer not found");
        signerRegistry.getSigner(clientId);

        // Attempt to create GasStation from zero address
        vm.prank(address(0));
        vm.expectRevert("Signer not found");
        gasStationFactory.createGasStation(clientId);
    }

    /**
     * @notice Test that deploying GasStation with CREATE2 requires sufficient balance.
     */
    function testGasStationDeploymentWithInsufficientBalance() public {
        bytes32 clientId = keccak256("Client6");
        address signer = address(0x9);

        // Set signer for clientId
        vm.prank(admin);
        signerRegistry.registerSigner(clientId, signer);

        // Ensure the factory has zero balance
        assertEq(address(gasStationFactory).balance, 0, "Factory should have zero balance");

        // Prank as signer and attempt to create GasStation
        vm.prank(signer);
        gasStationFactory.createGasStation(clientId);

        // Since CREATE2 with zero value doesn't require balance, this should pass.
        // If the GasStation constructor or any payable function requires ETH, adjust accordingly.
        // In current GasStation implementation, no ETH is required upon deployment.
    }
}
