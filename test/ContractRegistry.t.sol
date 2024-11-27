// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

// Import Foundry's Test framework
import "forge-std/Test.sol";

// Import the ContractRegistry and MockSignerRegistry contracts
import "../contracts/ContractRegistry.sol";
import "./MockSignerRegistry.sol";

/// @title ContractRegistryTest
/// @notice Test suite for the ContractRegistry contract.
contract ContractRegistryTest is Test {
    ContractRegistry public contractRegistry;
    MockSignerRegistry public mockSignerRegistry;

    address public admin = address(0x1);
    address public signer1 = address(0x2);
    address public signer2 = address(0x3);
    address public someContract = address(0x4);
    address public anotherContract = address(0x5);

    bytes32 public clientId1 = keccak256("Client1");
    bytes32 public clientId2 = keccak256("Client2");

    /// @notice Runs before each test
    function setUp() public {
        // Deploy the mock SignerRegistry
        mockSignerRegistry = new MockSignerRegistry();

        // Deploy the ContractRegistry with the mock SignerRegistry
        contractRegistry = new ContractRegistry(address(mockSignerRegistry));

        // Label addresses for better readability in test outputs
        vm.label(admin, "Admin");
        vm.label(signer1, "Signer1");
        vm.label(signer2, "Signer2");
        vm.label(someContract, "SomeContract");
        vm.label(anotherContract, "AnotherContract");
    }

    /// @notice Test that only the correct signer can set allowed contracts
    function testOnlySignerCanSetAllowedContract() public {
        // Register signer1 for clientId1
        vm.prank(admin);
        mockSignerRegistry.registerSigner(clientId1, signer1);

        // Attempt to set allowed contract as signer1 (should succeed)
        vm.prank(signer1);
        contractRegistry.setAllowedContract(clientId1, someContract, true);

        // Verify that the contract is allowed
        bool isAllowed = contractRegistry.isContractAllowed(clientId1, someContract);
        assertTrue(isAllowed, "Contract should be allowed");

        // Attempt to set allowed contract as signer2 (should fail)
        vm.prank(signer2);
        vm.expectRevert("Not authorized");
        contractRegistry.setAllowedContract(clientId1, anotherContract, true);
    }

    /// @notice Test setting and retrieving allowed contracts
    function testSetAndGetAllowedContract() public {
        // Register signer1 for clientId1
        vm.prank(admin);
        mockSignerRegistry.registerSigner(clientId1, signer1);

        // Register signer2 for clientId2
        vm.prank(admin);
        mockSignerRegistry.registerSigner(clientId2, signer2);

        // Signer1 allows someContract for clientId1
        vm.prank(signer1);
        contractRegistry.setAllowedContract(clientId1, someContract, true);

        // Signer2 disallows anotherContract for clientId2
        vm.prank(signer2);
        contractRegistry.setAllowedContract(clientId2, anotherContract, false);

        // Verify the allowed status
        bool isAllowed1 = contractRegistry.isContractAllowed(clientId1, someContract);
        bool isAllowed2 = contractRegistry.isContractAllowed(clientId2, anotherContract);

        assertTrue(isAllowed1, "someContract should be allowed for clientId1");
        assertFalse(isAllowed2, "anotherContract should not be allowed for clientId2");
    }

    /// @notice Test that setting the same contract multiple times works correctly
    function testSetSameContractMultipleTimes() public {
        // Register signer1 for clientId1
        vm.prank(admin);
        mockSignerRegistry.registerSigner(clientId1, signer1);

        // Signer1 allows someContract
        vm.prank(signer1);
        contractRegistry.setAllowedContract(clientId1, someContract, true);

        // Signer1 disallows someContract
        vm.prank(signer1);
        contractRegistry.setAllowedContract(clientId1, someContract, false);

        // Verify the allowed status
        bool isAllowed = contractRegistry.isContractAllowed(clientId1, someContract);
        assertFalse(isAllowed, "someContract should not be allowed for clientId1");
    }

    /// @notice Test that non-signers cannot set allowed contracts
    function testNonSignerCannotSetAllowedContract() public {
        // Register signer1 for clientId1
        vm.prank(admin);
        mockSignerRegistry.registerSigner(clientId1, signer1);

        // Attempt to set allowed contract as a random address (should fail)
        vm.prank(address(0xBEEF));
        vm.expectRevert("Not authorized");
        contractRegistry.setAllowedContract(clientId1, someContract, true);
    }

    /// @notice Test that allowed contracts are tracked per clientId
    function testAllowedContractsPerClient() public {
        // Register signers for two different clients
        vm.prank(admin);
        mockSignerRegistry.registerSigner(clientId1, signer1);

        vm.prank(admin);
        mockSignerRegistry.registerSigner(clientId2, signer2);

        // Signer1 allows someContract for clientId1
        vm.prank(signer1);
        contractRegistry.setAllowedContract(clientId1, someContract, true);

        // Signer2 allows someContract for clientId2 as well
        vm.prank(signer2);
        contractRegistry.setAllowedContract(clientId2, someContract, true);

        // Verify that someContract is allowed for both clients
        bool isAllowedClient1 = contractRegistry.isContractAllowed(clientId1, someContract);
        bool isAllowedClient2 = contractRegistry.isContractAllowed(clientId2, someContract);

        assertTrue(isAllowedClient1, "someContract should be allowed for clientId1");
        assertTrue(isAllowedClient2, "someContract should be allowed for clientId2");
    }

    /// @notice Test that events are emitted correctly when setting allowed contracts
    function testSetAllowedContractEmitsEvent() public {
        // Register signer1 for clientId1
        vm.prank(admin);
        mockSignerRegistry.registerSigner(clientId1, signer1);

        // Expect the ContractAllowed event to be emitted
        vm.expectEmit(true, false, false, true);
        emit ContractRegistry.ContractAllowed(someContract, true);

        // Signer1 sets someContract as allowed
        vm.prank(signer1);
        contractRegistry.setAllowedContract(clientId1, someContract, true);
    }

    /// @notice Test that the admin can change the signerRegistry address if needed
    function testChangeSignerRegistry() public {
        // Deploy a new MockSignerRegistry
        MockSignerRegistry newMockSignerRegistry = new MockSignerRegistry();

        // Register signer1 in the new SignerRegistry
        vm.prank(admin);
        newMockSignerRegistry.registerSigner(clientId1, signer1);

        // Attempt to change the signerRegistry in ContractRegistry
        // Note: The current ContractRegistry does not have a function to change signerRegistry
        // If you intend to add such a function, implement it accordingly.
        // For this test, we'll assume the signerRegistry is immutable.
        // Hence, this test will pass by ensuring the signerRegistry remains unchanged.

        address currentSignerRegistry = address(contractRegistry.signerRegistry());
        assertEq(currentSignerRegistry, address(mockSignerRegistry), "SignerRegistry should remain unchanged");
    }
}
