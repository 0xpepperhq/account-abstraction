// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

// Import Foundry's Test framework
import "forge-std/Test.sol";

// Import the WalletFactory, UserWallet, and SignerRegistry contracts
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {WalletFactory} from "../contracts/WalletFactory.sol";
import {UserWallet} from "../contracts/UserWallet.sol";
import {SignerRegistry} from "../contracts/SignerRegistry.sol";
import {ContractRegistry} from "../contracts/ContractRegistry.sol";

contract WalletFactoryTest is Test {
    WalletFactory public walletFactory;
    SignerRegistry public signerRegistry;
    ContractRegistry public contractRegistry;
    UserWallet public userWalletImplementation; // For reference, if needed

    // Define test addresses
    address public admin = address(0x1);
    address public relayer = address(0x2);
    address public signer1 = address(0x3);
    address public signer2 = address(0x4);
    address public nonAdmin = address(0x5);
    address public user1 = address(0x6);
    address public user2 = address(0x7);

    // Define test clientIds and userIds
    bytes32 public clientId1 = keccak256("Client1");
    bytes32 public clientId2 = keccak256("Client2");
    bytes32 public userId1 = keccak256("User1");
    bytes32 public userId2 = keccak256("User2");

    /// @notice Runs before each test
    function setUp() public {
        // Label addresses for better readability in test outputs
        vm.label(admin, "Admin");
        vm.label(relayer, "Relayer");
        vm.label(signer1, "Signer1");
        vm.label(signer2, "Signer2");
        vm.label(nonAdmin, "NonAdmin");
        vm.label(user1, "User1");
        vm.label(user2, "User2");

        // Deploy the SignerRegistry
        signerRegistry = new SignerRegistry(admin);

        // Deploy the ContractRegistry
        contractRegistry = new ContractRegistry(address(signerRegistry));

        // Prank as admin to register signers
        vm.startPrank(admin);
        signerRegistry.registerSigner(clientId1, signer1);
        signerRegistry.registerSigner(clientId2, signer2);
        vm.stopPrank();

        // Deploy the UserWallet implementation (for reference, not used directly)
        // Note: The implementation is not directly used since WalletFactory deploys new instances via CREATE2
        userWalletImplementation = new UserWallet(clientId1, relayer, address(contractRegistry), address(signerRegistry));

        // Deploy the WalletFactory contract with mock SignerRegistry, admin, relayer, ContractRegistry, and UserWallet implementation
        walletFactory = new WalletFactory(
            admin,
            relayer,
            address(contractRegistry),
            address(userWalletImplementation),
            address(signerRegistry)
        );

        // Fund the WalletFactory with some ETH if needed
        vm.deal(address(walletFactory), 10 ether);

        // Optionally, set allowed contracts in ContractRegistry if needed for tests
        // e.g., mockContractRegistry.setContractAllowed(clientId1, someContract, true);
    }

    /// @notice Test deployment and initial state
    function testDeployment() public view {
        assertEq(walletFactory.admin(), admin, "Admin should be set correctly");
        assertEq(walletFactory.relayer(), relayer, "Relayer should be set correctly");
        assertEq(walletFactory.contractRegistry(), address(contractRegistry), "ContractRegistry should be set correctly");
        assertEq(walletFactory.walletImplementation(), address(userWalletImplementation), "WalletImplementation should be set correctly");
        assertEq(walletFactory.signerRegistry(), address(signerRegistry), "SignerRegistry should be set correctly");

        // Check WalletFactory balance
        assertEq(address(walletFactory).balance, 10 ether, "WalletFactory should have 10 ether");
    }

    /// @notice Test that only admin can create a wallet
    function testCreateWallet_AsAdmin_Success() public {
        bytes32 userId = userId1;
        bytes32 clientId = clientId1;

        // Compute expected salt
        bytes32 salt = keccak256(abi.encodePacked(userId, clientId));

        // Compute expected wallet address
        bytes memory bytecode = abi.encodePacked(type(UserWallet).creationCode, abi.encode(clientId, relayer, address(contractRegistry), address(signerRegistry)));
        bytes32 codeHash = keccak256(bytecode);
        address expectedWalletAddress = Create2.computeAddress(salt, codeHash, address(walletFactory));

        // Expect WalletCreated event
        vm.expectEmit(true, true, false, true);
        emit WalletFactory.WalletCreated(userId, clientId, expectedWalletAddress);

        // Prank as admin and call createWallet
        vm.prank(admin);
        address walletAddress = walletFactory.createWallet(userId, clientId);

        // Verify the returned wallet address matches expected
        assertEq(walletAddress, expectedWalletAddress, "Wallet address should match expected CREATE2 address");

        // Verify that the wallet is deployed correctly
        assertTrue(walletAddress.code.length > 0, "Wallet should be deployed");

        // Verify that the mapping is updated
        address retrievedWallet = walletFactory.userWallets(clientId, userId);
        assertEq(retrievedWallet, walletAddress, "Wallet address should be mapped correctly");

        // Cast to UserWallet and verify constructor parameters
        UserWallet deployedWallet = UserWallet(payable(walletAddress));
        assertEq(deployedWallet.clientId(), clientId, "ClientId should be set correctly in UserWallet");
        assertEq(deployedWallet.relayer(), relayer, "Relayer should be set correctly in UserWallet");
        assertEq(address(deployedWallet.contractRegistry()), address(contractRegistry), "ContractRegistry should be set correctly in UserWallet");
        assertEq(address(deployedWallet.signerRegistry()), address(signerRegistry), "SignerRegistry should be set correctly in UserWallet");
    }

    /// @notice Test that non-admin cannot create a wallet
    function testCreateWallet_AsNonAdmin_Revert() public {
        bytes32 userId = userId1;
        bytes32 clientId = clientId1;

        vm.prank(nonAdmin);
        vm.expectRevert("Not authorized");
        walletFactory.createWallet(userId, clientId);
    }

    /// @notice Test that creating a wallet for an existing userId and clientId reverts
    function testCreateWallet_AlreadyExists_Revert() public {
        bytes32 userId = userId1;
        bytes32 clientId = clientId1;

        // Prank as admin and create the wallet first time
        vm.prank(admin);
        walletFactory.createWallet(userId, clientId);

        // Attempt to create the same wallet again
        vm.prank(admin);
        vm.expectRevert("Wallet already exists for this user");
        walletFactory.createWallet(userId, clientId);
    }

    /// @notice Test that computeWalletAddress returns the correct address
    function testComputeWalletAddress() public {
        bytes32 userId = userId2;
        bytes32 clientId = clientId2;

        // Compute expected salt
        bytes32 salt = keccak256(abi.encodePacked(userId, clientId));

        // Compute expected wallet address
        bytes memory bytecode = abi.encodePacked(type(UserWallet).creationCode, abi.encode(clientId, relayer, address(contractRegistry), address(signerRegistry)));
        bytes32 codeHash = keccak256(bytecode);
        address expectedWalletAddress = Create2.computeAddress(salt, codeHash, address(walletFactory));

        // Call computeWalletAddress
        address computedAddress = walletFactory.computeWalletAddress(userId, clientId);

        // Verify that the computed address matches expected
        assertEq(computedAddress, expectedWalletAddress, "Computed wallet address should match expected CREATE2 address");

        // Prank as admin and create the wallet
        vm.expectEmit(true, true, false, true);
        emit WalletFactory.WalletCreated(userId, clientId, expectedWalletAddress);
        vm.prank(admin);
        address deployedWalletAddress = walletFactory.createWallet(userId, clientId);

        // Verify that the deployed wallet address matches the computed address
        assertEq(deployedWalletAddress, expectedWalletAddress, "Deployed wallet address should match computed address");

        // Verify the wallet is deployed correctly
        assertTrue(expectedWalletAddress.code.length > 0, "Wallet should be deployed");
    }

    /// @notice Test that only admin can set a new admin
    function testSetAdmin_AsAdmin_Success() public {
        address newAdmin = address(0x9);

        // Expect AdminChanged event
        vm.expectEmit(true, true, false, true);
        emit WalletFactory.AdminChanged(admin, newAdmin);

        // Prank as admin and set new admin
        vm.prank(admin);
        walletFactory.setAdmin(newAdmin);

        // Verify admin is updated
        assertEq(walletFactory.admin(), newAdmin, "Admin should be updated to newAdmin");
    }

    /// @notice Test that non-admin cannot set a new admin
    function testSetAdmin_AsNonAdmin_Revert() public {
        address newAdmin = address(0x9);

        vm.prank(nonAdmin);
        vm.expectRevert("Not authorized");
        walletFactory.setAdmin(newAdmin);
    }

    /// @notice Test that setting admin to zero address reverts
    function testSetAdmin_ToZeroAddress_Revert() public {
        vm.prank(admin);
        vm.expectRevert("Invalid admin address");
        walletFactory.setAdmin(address(0));
    }

    /// @notice Test that only admin can set a new relayer
    function testSetRelayer_AsAdmin_Success() public {
        address newRelayer = address(0xA);

        // Expect RelayerChanged event
        vm.expectEmit(true, true, false, true);
        emit WalletFactory.RelayerChanged(relayer, newRelayer);

        // Prank as admin and set new relayer
        vm.prank(admin);
        walletFactory.setRelayer(newRelayer);

        // Verify relayer is updated
        assertEq(walletFactory.relayer(), newRelayer, "Relayer should be updated to newRelayer");
    }

    /// @notice Test that non-admin cannot set a new relayer
    function testSetRelayer_AsNonAdmin_Revert() public {
        address newRelayer = address(0xA);

        vm.prank(nonAdmin);
        vm.expectRevert("Not authorized");
        walletFactory.setRelayer(newRelayer);
    }

    /// @notice Test that setting relayer to zero address reverts
    function testSetRelayer_ToZeroAddress_Revert() public {
        vm.prank(admin);
        vm.expectRevert("Invalid relayer address");
        walletFactory.setRelayer(address(0));
    }

    /// @notice Test that only admin can set a new ContractRegistry
    function testSetContractRegistry_AsAdmin_Success() public {
        address newContractRegistry = address(0xB);

        // Expect ContractRegistryChanged event
        vm.expectEmit(true, true, false, true);
        emit WalletFactory.ContractRegistryChanged(address(walletFactory.contractRegistry()), newContractRegistry);

        // Prank as admin and set new ContractRegistry
        vm.prank(admin);
        walletFactory.setContractRegistry(newContractRegistry);

        // Verify ContractRegistry is updated
        assertEq(walletFactory.contractRegistry(), newContractRegistry, "ContractRegistry should be updated to newContractRegistry");
    }

    /// @notice Test that non-admin cannot set a new ContractRegistry
    function testSetContractRegistry_AsNonAdmin_Revert() public {
        address newContractRegistry = address(0xB);

        vm.prank(nonAdmin);
        vm.expectRevert("Not authorized");
        walletFactory.setContractRegistry(newContractRegistry);
    }

    /// @notice Test that setting ContractRegistry to zero address reverts
    function testSetContractRegistry_ToZeroAddress_Revert() public {
        vm.prank(admin);
        vm.expectRevert("Invalid contract registry address");
        walletFactory.setContractRegistry(address(0));
    }

    /// @notice Test that getWallet returns the correct wallet address
    function testGetWallet_ReturnsCorrectAddress() public {
        bytes32 userId = userId1;
        bytes32 clientId = clientId1;

        // Prank as admin and create the wallet
        vm.prank(admin);
        address walletAddress = walletFactory.createWallet(userId, clientId);

        // Call getWallet and verify
        address retrievedWallet = walletFactory.getWallet(clientId, userId);
        assertEq(retrievedWallet, walletAddress, "getWallet should return the correct wallet address");
    }

    /// @notice Test that getWallet returns zero address for non-existing wallet
    function testGetWallet_ReturnsZeroAddress_ForNonExistingWallet() public view {
        bytes32 userId = userId2;
        bytes32 clientId = clientId1;

        address retrievedWallet = walletFactory.getWallet(clientId, userId);
        assertEq(retrievedWallet, address(0), "getWallet should return zero address for non-existing wallet");
    }

    /// @notice Test that creating a wallet with unregistered clientId reverts
    function testCreateWallet_UnregisteredClientId_Revert() public {
        bytes32 userId = userId1;
        bytes32 clientId = keccak256("UnknownClient");

        vm.prank(admin);
        vm.expectRevert("Signer not found");
        walletFactory.createWallet(userId, clientId);
    }

    /// @notice Test that creating a wallet emits WalletCreated event correctly
    function testCreateWallet_EmitsWalletCreatedEvent() public {
        bytes32 userId = userId2;
        bytes32 clientId = clientId2;

        // Compute expected salt and wallet address
        bytes32 salt = keccak256(abi.encodePacked(userId, clientId));
        bytes memory bytecode = abi.encodePacked(type(UserWallet).creationCode, abi.encode(clientId, relayer, address(contractRegistry), address(signerRegistry)));
        bytes32 codeHash = keccak256(bytecode);
        address expectedWalletAddress = Create2.computeAddress(salt, codeHash, address(walletFactory));

        // Expect WalletCreated event
        vm.expectEmit(true, true, false, true);
        emit WalletFactory.WalletCreated(userId, clientId, expectedWalletAddress);

        // Prank as admin and create the wallet
        vm.prank(admin);
        walletFactory.createWallet(userId, clientId);
    }

    /// @notice Test that creating multiple wallets works correctly
    function testCreateMultipleWallets_Success() public {
        bytes32 userIdA = userId1;
        bytes32 clientIdA = clientId1;

        bytes32 userIdB = userId2;
        bytes32 clientIdB = clientId2;

        // Prank as admin and create the first wallet
        vm.prank(admin);
        address walletA = walletFactory.createWallet(userIdA, clientIdA);

        // Prank as admin and create the second wallet
        vm.prank(admin);
        address walletB = walletFactory.createWallet(userIdB, clientIdB);

        // Verify both wallets are deployed
        assertTrue(walletA.code.length > 0, "WalletA should be deployed");
        assertTrue(walletB.code.length > 0, "WalletB should be deployed");

        // Verify mappings
        assertEq(walletFactory.userWallets(clientIdA, userIdA), walletA, "WalletA should be mapped correctly");
        assertEq(walletFactory.userWallets(clientIdB, userIdB), walletB, "WalletB should be mapped correctly");

        // Optionally, verify that the wallets have correct clientIds
        UserWallet deployedWalletA = UserWallet(payable(walletA));
        UserWallet deployedWalletB = UserWallet(payable(walletB));
        assertEq(deployedWalletA.clientId(), clientId1, "ClientId should be set correctly in WalletA");
        assertEq(deployedWalletB.clientId(), clientId2, "ClientId should be set correctly in WalletB");
    }

    /// @notice Test that computeWalletAddress matches the deployed wallet address
    function testComputeWalletAddress_MatchesDeployedAddress() public {
        bytes32 userId = userId1;
        bytes32 clientId = clientId1;

        // Compute expected salt and wallet address
        bytes32 salt = keccak256(abi.encodePacked(userId, clientId));
        bytes memory bytecode = abi.encodePacked(type(UserWallet).creationCode, abi.encode(clientId, relayer, address(contractRegistry), address(signerRegistry)));
        bytes32 codeHash = keccak256(bytecode);
        address expectedWalletAddress = Create2.computeAddress(salt, codeHash, address(walletFactory));

        // Prank as admin and create the wallet
        vm.expectEmit(true, true, false, true);
        emit WalletFactory.WalletCreated(userId, clientId, expectedWalletAddress);
        vm.prank(admin);
        address deployedWalletAddress = walletFactory.createWallet(userId, clientId);

        // Compute via factory's computeWalletAddress
        address computedAddress = walletFactory.computeWalletAddress(userId, clientId);

        // Verify that computed address matches deployed address
        assertEq(computedAddress, deployedWalletAddress, "Computed address should match deployed address");
    }

    /// @notice Test that creating a wallet with zero signer address reverts
    function testCreateWallet_ZeroSignerAddress_Revert() public {
        bytes32 userId = userId1;
        bytes32 clientId = keccak256("Client3"); // Assume Client3 is not registered

        // Prank as admin and attempt to create wallet with zero signer
        // Since Client3 is not registered, getSigner would return zero and revert
        vm.prank(admin);
        vm.expectRevert("Signer not found");
        walletFactory.createWallet(userId, clientId);
    }

    /// @notice Test that creating a wallet with blocked signer reverts
    function testCreateWallet_BlockedSigner_Revert() public {
        bytes32 userId = userId1;
        bytes32 clientId = clientId1;

        // Prank as admin and block signer1 in SignerRegistry
        vm.prank(admin);
        signerRegistry.blockSigner(signer1);

        // Prank as admin and attempt to create wallet
        vm.prank(admin);
        vm.expectRevert("Signer is blocked");
        walletFactory.createWallet(userId, clientId);
    }

    /// @notice Test that WalletFactory cannot deploy wallet with insufficient funds
    function testCreateWallet_InsufficientFactoryBalance_Success() public {
        bytes32 userId = userId1;
        bytes32 clientId = clientId1;

        // Set WalletFactory balance to zero
        vm.deal(address(walletFactory), 0);

        // Prank as admin and attempt to create wallet
        // Assuming UserWallet does not require ETH in constructor, this should pass
        vm.expectEmit(true, true, false, true);
        bytes memory bytecode = abi.encodePacked(type(UserWallet).creationCode, abi.encode(clientId, relayer, address(contractRegistry), address(signerRegistry)));
        bytes32 codeHash = keccak256(bytecode);
        bytes32 salt = keccak256(abi.encodePacked(userId, clientId));
        address expectedWalletAddress = Create2.computeAddress(salt, codeHash, address(walletFactory));
        emit WalletFactory.WalletCreated(userId, clientId, expectedWalletAddress);
        vm.prank(admin);
        address walletAddress = walletFactory.createWallet(userId, clientId);

        // Verify wallet is deployed
        assertTrue(walletAddress.code.length > 0, "Wallet should be deployed even with zero factory balance");
    }

    /// @notice Test that WalletFactory can deploy multiple wallets for the same signer
    function testCreateMultipleWallets_SameSigner_Success() public {
        bytes32 userIdA = userId1;
        bytes32 clientIdA = clientId1;

        bytes32 userIdB = userId2;
        bytes32 clientIdB = clientId1; // Same clientId as clientIdA

        // Prank as admin and create the first wallet
        vm.prank(admin);
        address walletA = walletFactory.createWallet(userIdA, clientIdA);

        // Prank as admin and create the second wallet with same clientId but different userId
        vm.prank(admin);
        address walletB = walletFactory.createWallet(userIdB, clientIdB);

        // Verify both wallets are deployed
        assertTrue(walletA.code.length > 0, "WalletA should be deployed");
        assertTrue(walletB.code.length > 0, "WalletB should be deployed");

        // Verify mappings
        assertEq(walletFactory.userWallets(clientIdA, userIdA), walletA, "WalletA should be mapped correctly");
        assertEq(walletFactory.userWallets(clientIdB, userIdB), walletB, "WalletB should be mapped correctly");

        // Verify that both wallets have the same signer (signer1)
        UserWallet deployedWalletA = UserWallet(payable(walletA));
        UserWallet deployedWalletB = UserWallet(payable(walletB));
        assertEq(address(deployedWalletA.signerRegistry()), address(signerRegistry), "SignerRegistry should be set correctly in WalletA");
        assertEq(address(deployedWalletB.signerRegistry()), address(signerRegistry), "SignerRegistry should be set correctly in WalletB");
    }
}
