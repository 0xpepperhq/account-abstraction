// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

// Import Foundry's Test framework
import "forge-std/Test.sol";

// Import the SignerRegistry contract
import "../contracts/SignerRegistry.sol";

/// @title SignerRegistryTest
/// @notice Test suite for the SignerRegistry contract.
contract SignerRegistryTest is Test {
    SignerRegistry public signerRegistry;

    // Define test addresses
    address public admin = address(0x1);
    address public signer1 = address(0x2);
    address public signer2 = address(0x3);
    address public blockedSigner = address(0x4);
    address public nonAdmin = address(0x5);

    // Define test clientIds
    bytes32 public clientId1 = keccak256("Client1");
    bytes32 public clientId2 = keccak256("Client2");
    bytes32 public clientId3 = keccak256("Client3");

    /// @notice Runs before each test
    function setUp() public {
        // Label addresses for better readability in test outputs
        vm.label(admin, "Admin");
        vm.label(signer1, "Signer1");
        vm.label(signer2, "Signer2");
        vm.label(blockedSigner, "BlockedSigner");
        vm.label(nonAdmin, "NonAdmin");

        // Deploy the SignerRegistry contract with admin
        vm.startPrank(admin);
        signerRegistry = new SignerRegistry(admin);
        vm.stopPrank();
    }

    /// @notice Test that the contract is deployed with the correct admin
    function testDeployment() public {
        assertEq(signerRegistry.admin(), admin, "Admin should be set correctly");
    }

    /// @notice Test that deploying with zero address as admin reverts
    function testConstructor_RevertIfAdminZeroAddress() public {
        vm.expectRevert("Invalid admin address");
        new SignerRegistry(address(0));
    }

    /// @notice Test that only admin can register a signer
    function testRegisterSigner_AsAdmin() public {
        vm.prank(admin);
        vm.expectEmit(true, true, false, true);
        emit SignerRegistry.SignerRegistered(clientId1, signer1);
        signerRegistry.registerSigner(clientId1, signer1);

        // Verify that the signer is set correctly
        address retrievedSigner = signerRegistry.getSigner(clientId1);
        assertEq(retrievedSigner, signer1, "Signer1 should be registered for Client1");
    }

    function testRegisterSigner_AsNonAdmin_Revert() public {
        vm.prank(nonAdmin);
        vm.expectRevert("Not authorized");
        signerRegistry.registerSigner(clientId1, signer1);
    }

    /// @notice Test that registering a signer emits the correct event
    function testRegisterSigner_EmitsEvent() public {
        vm.prank(admin);
        vm.expectEmit(true, true, false, true);
        emit SignerRegistry.SignerRegistered(clientId2, signer2);
        signerRegistry.registerSigner(clientId2, signer2);
    }

    /// @notice Test that getSigner returns the correct signer
    function testGetSigner_ReturnsCorrectSigner() public {
        vm.prank(admin);
        signerRegistry.registerSigner(clientId1, signer1);

        address retrievedSigner = signerRegistry.getSigner(clientId1);
        assertEq(retrievedSigner, signer1, "getSigner should return signer1 for Client1");
    }

    /// @notice Test that getSigner reverts if signer is not registered
    function testGetSigner_RevertIfSignerNotRegistered() public {
        vm.expectRevert("Signer not found");
        signerRegistry.getSigner(clientId3);
    }

    /// @notice Test that getSigner reverts if signer is blocked
    function testGetSigner_RevertIfSignerBlocked() public {
        // Register a signer
        vm.prank(admin);
        signerRegistry.registerSigner(clientId1, blockedSigner);

        // Block the signer
        vm.prank(admin);
        signerRegistry.blockSigner(blockedSigner);

        // Attempt to get the blocked signer
        vm.expectRevert("Signer is blocked");
        signerRegistry.getSigner(clientId1);
    }

    /// @notice Test that only admin can block a signer
    function testBlockSigner_AsAdmin() public {
        // Register a signer first
        vm.prank(admin);
        signerRegistry.registerSigner(clientId1, signer1);

        // Block the signer
        vm.prank(admin);
        signerRegistry.blockSigner(signer1);

        // Attempt to get the signer should revert
        vm.expectRevert("Signer is blocked");
        signerRegistry.getSigner(clientId1);
    }

    function testBlockSigner_AsNonAdmin_Revert() public {
        // Register a signer first
        vm.prank(admin);
        signerRegistry.registerSigner(clientId1, signer1);

        // Attempt to block as non-admin
        vm.prank(nonAdmin);
        vm.expectRevert("Not authorized");
        signerRegistry.blockSigner(signer1);
    }

    /// @notice Test that blocking a signer emits the correct state change
    function testBlockSigner_EmitsStateChange() public {
        // Register a signer first
        vm.prank(admin);
        signerRegistry.registerSigner(clientId1, signer1);

        // Block the signer
        vm.prank(admin);
        signerRegistry.blockSigner(signer1);

        // Verify that the signer is blocked
        // Since there is no event for blocking, we check via getSigner
        vm.expectRevert("Signer is blocked");
        signerRegistry.getSigner(clientId1);
    }

    /// @notice Test that only admin can set a new admin
    function testSetAdmin_AsAdmin() public {
        vm.prank(admin);
        vm.expectEmit(true, true, false, true);
        emit SignerRegistry.AdminChanged(admin, nonAdmin);
        signerRegistry.setAdmin(nonAdmin);

        // Verify that the admin is updated
        assertEq(signerRegistry.admin(), nonAdmin, "Admin should be updated to NonAdmin");
    }

    function testSetAdmin_AsNonAdmin_Revert() public {
        vm.prank(nonAdmin);
        vm.expectRevert("Not authorized");
        signerRegistry.setAdmin(address(0x6));
    }

    /// @notice Test that setting admin to zero address reverts
    function testSetAdmin_RevertIfNewAdminZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert("Invalid admin address");
        signerRegistry.setAdmin(address(0));
    }

    /// @notice Test that after changing admin, the new admin has control
    function testSetAdmin_NewAdminCanRegisterSigner() public {
        // Change admin to nonAdmin
        vm.prank(admin);
        signerRegistry.setAdmin(nonAdmin);

        // Old admin should no longer be able to register a signer
        vm.prank(admin);
        vm.expectRevert("Not authorized");
        signerRegistry.registerSigner(clientId1, signer1);

        // New admin can register a signer
        vm.prank(nonAdmin);
        signerRegistry.registerSigner(clientId1, signer1);

        // Verify the signer is registered
        address retrievedSigner = signerRegistry.getSigner(clientId1);
        assertEq(retrievedSigner, signer1, "Signer1 should be registered for Client1 by new admin");
    }

    /// @notice Test that a signer can be re-registered
    function testRegisterSigner_ReRegisterClientId() public {
        vm.prank(admin);
        signerRegistry.registerSigner(clientId1, signer1);

        // Re-register with a different signer
        vm.prank(admin);
        signerRegistry.registerSigner(clientId1, signer2);

        // Verify that the signer is updated
        address retrievedSigner = signerRegistry.getSigner(clientId1);
        assertEq(retrievedSigner, signer2, "Signer2 should be registered for Client1 after re-registration");
    }

    /// @notice Test that blocking a signer after re-registration works correctly
    function testBlockSigner_AfterReRegisteringSigner() public {
        vm.prank(admin);
        signerRegistry.registerSigner(clientId1, signer1);

        // Re-register with a different signer
        vm.prank(admin);
        signerRegistry.registerSigner(clientId1, signer2);

        // Block signer2
        vm.prank(admin);
        signerRegistry.blockSigner(signer2);

        // Attempt to get the signer should revert
        vm.expectRevert("Signer is blocked");
        signerRegistry.getSigner(clientId1);
    }

    /// @notice Test that blocking a signer does not affect other clientIds
    function testBlockSigner_DoesNotAffectOtherClientIds() public {
        // Register signers for different clientIds
        vm.prank(admin);
        signerRegistry.registerSigner(clientId1, signer1);

        vm.prank(admin);
        signerRegistry.registerSigner(clientId2, signer2);

        // Block signer1
        vm.prank(admin);
        signerRegistry.blockSigner(signer1);

        // Attempt to get signer1 for clientId1 should revert
        vm.expectRevert("Signer is blocked");
        signerRegistry.getSigner(clientId1);

        // signer2 for clientId2 should still be retrievable
        address retrievedSigner = signerRegistry.getSigner(clientId2);
        assertEq(retrievedSigner, signer2, "Signer2 should still be retrievable for Client2");
    }
}
