// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

// Import Foundry's Test framework
import "forge-std/Test.sol";

// Import the GasStation and MockSignerRegistry contracts
import "../contracts/GasStation.sol";
import "../contracts/SignerRegistry.sol";

/// @title GasStationTest
/// @notice Test suite for the GasStation contract.
contract GasStationTest is Test {
    GasStation public gasStation;
    SignerRegistry public mockSignerRegistry;

    // Define test addresses
    address public admin = address(0x1);
    address public relayer = address(0x2);
    address public signer1 = address(0x3);
    address public signer2 = address(0x4);
    address public nonRelayer = address(0x5);
    address public nonAdmin = address(0x6);
    address public nonSigner = address(0x7);
    address public someContract = address(0x8);

    // Define test clientIds
    bytes32 public clientId1 = keccak256("Client1");
    bytes32 public clientId2 = keccak256("Client2");

    /// @notice Runs before each test
    function setUp() public {
        // Label addresses for better readability in test outputs
        vm.label(admin, "Admin");
        vm.label(relayer, "Relayer");
        vm.label(signer1, "Signer1");
        vm.label(signer2, "Signer2");
        vm.label(nonRelayer, "NonRelayer");
        vm.label(nonAdmin, "NonAdmin");
        vm.label(nonSigner, "NonSigner");
        vm.label(someContract, "SomeContract");

        // Deploy the MockSignerRegistry
        mockSignerRegistry = new SignerRegistry(admin);

        // Register signers
        vm.prank(admin);
        mockSignerRegistry.registerSigner(clientId1, signer1);

        vm.prank(admin);
        mockSignerRegistry.registerSigner(clientId2, signer2);

        // Deploy the GasStation contract with mock SignerRegistry, admin, relayer
        gasStation = new GasStation(address(mockSignerRegistry), admin, relayer);

        // Fund the GasStation with 1 ether
        vm.deal(address(gasStation), 1 ether);
    }

    /// @notice Test deployment and initial state
    function testDeployment() public {
        assertEq(gasStation.admin(), admin, "Admin should be set correctly");
        assertEq(gasStation.relayer(), relayer, "Relayer should be set correctly");
        assertEq(address(gasStation.signerRegistry()), address(mockSignerRegistry), "SignerRegistry should be set correctly");

        // Check GasStation balance
        assertEq(address(gasStation).balance, 1 ether, "GasStation should have 1 ether");
    }

    /// @notice Test that only relayer can call provideGas
    function testProvideGas_AsRelayer_Success() public {
        uint256 amount = 0.005 ether;

        // Check relayer's initial balance
        uint256 relayerInitialBalance = relayer.balance;

        // Expect GasProvided event
        vm.expectEmit(true, true, false, true);
        emit GasStation.GasProvided(relayer, amount);

        // Prank as relayer and call provideGas
        vm.prank(relayer);
        gasStation.provideGas(amount);

        // Check GasStation balance decreased
        assertEq(address(gasStation).balance, 1 ether - amount, "GasStation balance should decrease by amount");

        // Check relayer's balance increased
        assertEq(relayer.balance, relayerInitialBalance + amount, "Relayer balance should increase by amount");
    }

    /// @notice Test that non-relayer cannot call provideGas
    function testProvideGas_AsNonRelayer_Revert() public {
        uint256 amount = 0.005 ether;

        vm.prank(nonRelayer);
        vm.expectRevert("Not authorized");
        gasStation.provideGas(amount);
    }

    /// @notice Test that provideGas fails when amount exceeds MAX_GAS_WITHDRAWAL
    function testProvideGas_ExceedsLimit_Revert() public {
        uint256 amount = 0.02 ether; // exceeds 0.01 ether

        vm.prank(relayer);
        vm.expectRevert("Exceeds max gas withdrawal limit");
        gasStation.provideGas(amount);
    }

    /// @notice Test that provideGas fails when GasStation has insufficient balance
    function testProvideGas_InsufficientBalance_Revert() public {
        uint256 amount = 0.005 ether;

        // Set GasStation balance to less than amount
        vm.deal(address(gasStation), 0.003 ether);

        vm.prank(relayer);
        vm.expectRevert("Insufficient gas station balance");
        gasStation.provideGas(amount);
    }

    /// @notice Test that only admin can call setRelayer
    function testSetRelayer_AsAdmin_Success() public {
        address newRelayer = address(0x9);

        // Expect RelayerChanged event
        vm.expectEmit(true, true, false, true);
        emit GasStation.RelayerChanged(relayer, newRelayer);

        // Prank as admin and set new relayer
        vm.prank(admin);
        gasStation.setRelayer(newRelayer);

        // Verify relayer updated
        assertEq(gasStation.relayer(), newRelayer, "Relayer should be updated to newRelayer");
    }

    /// @notice Test that non-admin cannot call setRelayer
    function testSetRelayer_AsNonAdmin_Revert() public {
        address newRelayer = address(0x9);

        vm.prank(nonAdmin);
        vm.expectRevert("Not authorized");
        gasStation.setRelayer(newRelayer);
    }

    /// @notice Test that setRelayer cannot set relayer to zero address
    function testSetRelayer_ToZeroAddress_Revert() public {
        vm.prank(admin);
        vm.expectRevert("Invalid relayer address");
        gasStation.setRelayer(address(0));
    }

    /// @notice Test that only signer can call withdraw
    function testWithdraw_AsSigner_Success() public {
        bytes32 clientId = clientId1;
        uint256 amount = 0.1 ether;

        // Fund GasStation with additional ether
        vm.deal(address(gasStation), 1 ether + amount);

        // Reset signer1's balance to zero
        vm.deal(signer1, 0);

        // Prank as signer1 and call withdraw
        vm.prank(signer1);
        gasStation.withdraw(clientId, amount);

        // Check signer1's balance increased by amount
        assertEq(signer1.balance, amount, "Signer1 should receive the withdrawn amount");

        // Check GasStation balance decreased by amount
        assertEq(address(gasStation).balance, 1 ether, "GasStation balance should decrease by amount");
    }

    /// @notice Test that non-signer cannot call withdraw
    function testWithdraw_AsNonSigner_Revert() public {
        bytes32 clientId = clientId1;
        uint256 amount = 0.1 ether;

        vm.prank(nonSigner);
        vm.expectRevert("Not authorized");
        gasStation.withdraw(clientId, amount);
    }

    /// @notice Test that withdraw fails when amount exceeds GasStation's balance
    function testWithdraw_InsufficientBalance_Revert() public {
        bytes32 clientId = clientId1;
        uint256 amount = 2 ether; // GasStation has 1 ether

        vm.prank(signer1);
        vm.expectRevert("Insufficient balance");
        gasStation.withdraw(clientId, amount);
    }

    /// @notice Test that withdraw reverts when signer is not registered
    function testWithdraw_SignerNotRegistered_Revert() public {
        bytes32 clientId = keccak256("UnknownClient");
        uint256 amount = 0.1 ether;

        vm.prank(nonSigner);
        vm.expectRevert("Signer not found"); // because getSigner would revert with "Signer not found"
        gasStation.withdraw(clientId, amount);
    }

    /// @notice Test that withdraw reverts when signer is blocked
    function testWithdraw_SignerBlocked_Revert() public {
        bytes32 clientId = clientId1;
        uint256 amount = 0.1 ether;

        // Prank as admin and block signer1 in MockSignerRegistry
        vm.prank(admin);
        mockSignerRegistry.blockSigner(signer1);

        // Prank as signer1 and attempt to withdraw
        vm.prank(signer1);
        vm.expectRevert("Signer is blocked");
        gasStation.withdraw(clientId, amount);
    }

    /// @notice Test that withdraw transfers ETH to the correct signer
    function testWithdraw_TransfersToCorrectSigner() public {
        bytes32 clientId = clientId2;
        uint256 amount = 0.2 ether;

        // Prank as signer2 and call withdraw
        // Reset signer2's balance to zero
        vm.deal(signer2, 0);

        // Fund GasStation with additional ether
        vm.deal(address(gasStation), 1 ether + amount);

        vm.prank(signer2);
        gasStation.withdraw(clientId, amount);

        // Check signer2's balance increased by amount
        assertEq(signer2.balance, amount, "Signer2 should receive the withdrawn amount");
    }

    /// @notice Test that provideGas emits GasProvided event correctly
    function testProvideGas_EmitsGasProvidedEvent() public {
        uint256 amount = 0.005 ether;

        vm.expectEmit(true, true, false, true);
        emit GasStation.GasProvided(relayer, amount);

        vm.prank(relayer);
        gasStation.provideGas(amount);
    }

    /// @notice Test that setRelayer emits RelayerChanged event correctly
    function testSetRelayer_EmitsRelayerChangedEvent() public {
        address newRelayer = address(0x9);

        vm.expectEmit(true, true, false, true);
        emit GasStation.RelayerChanged(relayer, newRelayer);

        vm.prank(admin);
        gasStation.setRelayer(newRelayer);
    }

    /// @notice Test that withdrawing emits no event
    function testWithdraw_DoesNotEmitEvent() public {
        bytes32 clientId = clientId1;
        uint256 amount = 0.1 ether;

        // Prank as signer1 and call withdraw
        // Reset signer1's balance to zero
        vm.deal(signer1, 0);

        // Fund GasStation with additional ether
        vm.deal(address(gasStation), 1 ether + amount);

        // Expect no events to be emitted
        vm.recordLogs();

        vm.prank(signer1);
        gasStation.withdraw(clientId, amount);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        assertEq(entries.length, 0, "No events should be emitted on withdraw");
    }

    /// @notice Test that providing gas more than the balance reverts
    function testProvideGas_AmountMoreThanBalance_Revert() public {
        uint256 amount = 0.01 ether; // GasStation has 1 ether
        GasStation newGasStation = new GasStation(address(mockSignerRegistry), admin, relayer);

        vm.prank(relayer);
        vm.expectRevert("Insufficient gas station balance");
        newGasStation.provideGas(amount);
    }

    /// @notice Test that withdrawing zero amount transfers zero ETH
    function testWithdraw_ZeroAmount_Success() public {
        bytes32 clientId = clientId1;
        uint256 amount = 0;

        // Prank as signer1 and call withdraw with zero
        vm.prank(signer1);
        gasStation.withdraw(clientId, amount);

        // Check signer1's balance remains unchanged
        assertEq(signer1.balance, 0, "Signer1's balance should remain unchanged");
    }

    /// @notice Test that providing zero amount does not change balances
    function testProvideGas_ZeroAmount_Success() public {
        uint256 amount = 0;

        // Prank as relayer and call provideGas
        vm.prank(relayer);
        gasStation.provideGas(amount);

        // Check GasStation balance remains the same
        assertEq(address(gasStation).balance, 1 ether, "GasStation balance should remain unchanged");

        // Check relayer's balance remains the same
        assertEq(relayer.balance, 0, "Relayer balance should remain unchanged");
    }

    /// @notice Test that setting relayer to the same address works correctly
    function testSetRelayer_SameAddress_Success() public {
        address currentRelayer = relayer;

        vm.expectEmit(true, true, false, true);
        emit GasStation.RelayerChanged(currentRelayer, currentRelayer);

        vm.prank(admin);
        gasStation.setRelayer(currentRelayer);

        // Verify relayer remains unchanged
        assertEq(gasStation.relayer(), currentRelayer, "Relayer should remain unchanged");
    }
}
