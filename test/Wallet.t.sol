// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

// Import Foundry's Test framework
import "forge-std/Test.sol";

// Import the Wallet and other contracts
import {Wallet} from "../contracts/Wallet.sol";
import {ContractRegistry} from "../contracts/ContractRegistry.sol";
import {SignerRegistry} from "../contracts/SignerRegistry.sol";
import "../contracts/Types.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract WalletTest is Test {
    using stdStorage for StdStorage;
    using SafeERC20 for IERC20;

    // Contracts under test
    Wallet public wallet;
    ContractRegistry public contractRegistry;
    SignerRegistry public signerRegistry;
    MockTargetContract public mockTargetContract; // New mock contract

    // Test addresses
    address public admin = address(0x1);
    address public relayer = address(0x2);
    address public signer; // Dynamic signer address
    address public nonSigner = address(0x4);
    address public targetContract; // Updated to point to mockTargetContract
    address public anotherContract = address(0x6);

    // Test clientId and userId
    bytes32 public clientId = keccak256("Client1");
    bytes32 public userId = keccak256("User1");

    // EIP-712 domain parameters
    string public constant name = "Wallet";

    // EIP-712 domain separator
    bytes32 public DOMAIN_SEPARATOR;

    // Private key for signer
    uint256 public constant signerPrivateKey = 0xA11CE; // Example private key

    /// @notice Runs before each test
    function setUp() public {
        // Label addresses for better readability in test outputs
        vm.label(admin, "Admin");
        vm.label(relayer, "Relayer");
        vm.label(address(0x3), "Signer"); // Temporary label
        vm.label(nonSigner, "NonSigner");
        vm.label(targetContract, "TargetContract"); // Will update after deploying mock
        vm.label(anotherContract, "AnotherContract");

        // Derive signer address from private key
        signer = vm.addr(signerPrivateKey);
        vm.label(signer, "Signer"); // Update label to actual signer

        // Deploy SignerRegistry and ContractRegistry
        signerRegistry = new SignerRegistry(admin);
        contractRegistry = new ContractRegistry(address(signerRegistry));

        // Register signer for clientId
        vm.startPrank(admin);
        signerRegistry.registerSigner(clientId, signer);
        vm.stopPrank();

        // Deploy MockTargetContract and set targetContract to its address
        mockTargetContract = new MockTargetContract();
        targetContract = address(mockTargetContract);
        vm.label(targetContract, "MockTargetContract"); // Update label

        // Allow targetContract in ContractRegistry
        vm.startPrank(signer);
        contractRegistry.setAllowedContract(clientId, targetContract, true);
        contractRegistry.setAllowedContract(clientId, anotherContract, false); // Disallowed
        vm.stopPrank();

        // Deploy Wallet
        wallet = new Wallet(clientId, relayer, address(contractRegistry), address(signerRegistry));

        // Fund Wallet with ETH for reimbursements
        vm.deal(address(wallet), 10 ether);

        // Initialize DOMAIN_SEPARATOR
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                wallet.DOMAIN_TYPEHASH(),
                keccak256(bytes(name)),
                block.chainid,
                address(wallet)
            )
        );
    }

    /// @notice Helper function to generate EIP-712 signature
    function _signExecuteAction(
        address to,
        uint256 value,
        bytes memory data,
        uint256 _nonce,
        Types.ReimburseGas memory gasParams
    ) internal returns (bytes memory) {
        // Compute the message hash
        bytes32 gasStructHash = keccak256(
            abi.encode(
                wallet.REIMBURSE_GAS_TYPEHASH(),
                gasParams.gasPrice,
                gasParams.gasLimit,
                gasParams.reimburse,
                gasParams.reimburseInNative,
                gasParams.tokenRate,
                gasParams.token
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                wallet.EXECUTE_ACTION_TYPEHASH(),
                to,
                value,
                keccak256(data),
                _nonce,
                gasStructHash
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", wallet.DOMAIN_SEPARATOR(), structHash)
        );

        // Sign the digest using the signer's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Test that the Wallet is initialized correctly
    function testInitialization() public {
        assertEq(wallet.clientId(), clientId, "ClientId should be set correctly");
        assertEq(wallet.relayer(), relayer, "Relayer should be set correctly");
        assertEq(address(wallet.contractRegistry()), address(contractRegistry), "ContractRegistry should be set correctly");
        assertEq(address(wallet.signerRegistry()), address(signerRegistry), "SignerRegistry should be set correctly");
        assertEq(wallet.nonce(), 0, "Initial nonce should be zero");
        assertEq(wallet.DOMAIN_SEPARATOR(), DOMAIN_SEPARATOR, "Domain separator should be initialized correctly");
    }

    /// @notice Test that Wallet can receive Ether via receive() function
    function testReceiveEther() public {
        vm.deal(address(this), 1 ether);
        vm.prank(address(this));
        (bool sent, ) = address(wallet).call{value: 1 ether}("");
        require(sent, "Failed to send Ether");

        assertEq(address(wallet).balance, 11 ether, "Wallet should have received 1 ether");
    }

    /// @notice Test that Wallet can receive Ether via fallback() function
    function testFallbackEther() public {
        bytes memory data = hex"1234";
        vm.deal(address(this), 1 ether);
        vm.prank(address(this));
        (bool sent, ) = address(wallet).call{value: 1 ether}(data);
        require(sent, "Failed to send Ether via fallback");

        assertEq(address(wallet).balance, 11 ether, "Wallet should have received 1 ether via fallback");
    }

    /// @notice Test that executeAction works correctly with valid parameters and signature
    function testExecuteAction_Success() public {
        // Prepare action parameters
        address to = targetContract;
        uint256 value = 1 ether;
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: true,
            tokenRate: 0, // Not used when reimburseInNative is true
            token: address(0) // Not used when reimburseInNative is true
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Expect ActionExecuted event
        vm.expectEmit(true, true, false, true);
        emit Wallet.ActionExecuted(to, value, callData);

        // Prank as relayer and call executeAction
        vm.prank(relayer);
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);

        // Verify nonce incremented
        assertEq(wallet.nonce(), 1, "Nonce should be incremented");

        // Verify that targetContract received the Ether
        assertEq(targetContract.balance, 1 ether, "Target contract should have received 1 ether");

        // Verify that relayer received gas reimbursement
        // Note: Foundry does not track exact gas used, so precise balance checks aren't feasible here
        // Consider mocking gas reimbursement if precise testing is required
    }

    /// @notice Test that executeAction reverts when called by non-relayer
    function testExecuteAction_AsNonRelayer_Revert() public {
        // Prepare action parameters
        address to = targetContract;
        uint256 value = 1 ether;
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: true,
            tokenRate: 0,
            token: address(0)
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Prank as non-relayer and attempt to call executeAction
        vm.prank(nonSigner);
        vm.expectRevert("Not authorized");
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
    }

    /// @notice Test that executeAction reverts when called for a disallowed contract
    function testExecuteAction_DisallowedContract_Revert() public {
        // Prepare action parameters
        address to = anotherContract; // Disallowed contract
        uint256 value = 1 ether;
        bytes memory callData = abi.encodeWithSignature("bar()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: true,
            tokenRate: 0,
            token: address(0)
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Prank as relayer and attempt to call executeAction
        vm.prank(relayer);
        vm.expectRevert("Contract not allowed");
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
    }

    /// @notice Test that executeAction reverts with invalid signature
    function testExecuteAction_InvalidSignature_Revert() public {
        // Prepare action parameters
        address to = targetContract;
        uint256 value = 1 ether;
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: true,
            tokenRate: 0,
            token: address(0)
        });

        // Generate invalid signature (e.g., tampered)
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);
        // Tamper with the signature by flipping a byte
        signature[10] = ~signature[10];

        // Prank as relayer and attempt to call executeAction
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
    }

    /// @notice Test that executeAction reverts with incorrect nonce
    function testExecuteAction_IncorrectNonce_Revert() public {
        // Prepare action parameters
        address to = targetContract;
        uint256 value = 1 ether;
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 1; // Incorrect nonce

        // Prepare gas reimbursement parameters
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: true,
            tokenRate: 0,
            token: address(0)
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Prank as relayer and attempt to call executeAction
        vm.prank(relayer);
        vm.expectRevert("Invalid nonce");
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
    }

    /// @notice Test that executeAction reverts when gas price is too high
    function testExecuteAction_GasPriceTooHigh_Revert() public {
        // Prepare action parameters
        address to = targetContract;
        uint256 value = 1 ether;
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters with gasPrice > MAX_GAS_PRICE (assumed to be 200 gwei)
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 300 gwei, // Too high
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: true,
            tokenRate: 0,
            token: address(0)
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Prank as relayer and attempt to call executeAction
        vm.prank(relayer);
        vm.expectRevert("Gas price too high");
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
    }

    /// @notice Test that executeAction reverts when gas limit is too high
    function testExecuteAction_GasLimitTooHigh_Revert() public {
        // Prepare action parameters
        address to = targetContract;
        uint256 value = 1 ether;
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters with gasLimit > MAX_GAS_LIMIT (assumed to be 500,000)
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 600000, // Too high
            reimburse: true,
            reimburseInNative: true,
            tokenRate: 0,
            token: address(0)
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Prank as relayer and attempt to call executeAction
        vm.prank(relayer);
        vm.expectRevert("Gas limit too high");
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
    }

    /// @notice Test that executeAction reimburses relayer in native tokens correctly
    function testExecuteAction_ReimburseInNative_Success() public {
        // Prepare action parameters
        address to = targetContract;
        uint256 value = 0; // No Ether transfer
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: true,
            tokenRate: 0, // Not used when reimburseInNative is true
            token: address(0) // Not used when reimburseInNative is true
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Record relayer balance before
        uint256 relayerBalanceBefore = relayer.balance;
        uint256 userWalletBalanceBefore = address(wallet).balance;

        // Prank as relayer and call executeAction
        vm.prank(relayer);
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);

        // Record relayer balance after
        uint256 relayerBalanceAfter = relayer.balance;
        uint256 userWalletBalanceAfter = address(wallet).balance;

        uint256 gasPaid = userWalletBalanceBefore - userWalletBalanceAfter;
        uint256 reimbursement = relayerBalanceAfter - relayerBalanceBefore;

        assertGt(gasPaid, 0, "Gas should be paid by Wallet");
        assertEq(gasPaid, reimbursement, "Relayer should be reimbursed correctly");
        assertLt(address(wallet).balance, userWalletBalanceBefore, "Wallet should have paid gas fees");
    }

    /// @notice Test that withdraw function works correctly when called by signer
    function testWithdraw_Ether_Success() public {
        address user10 = address(0x10);
        // Prank as signer and call withdraw
        vm.prank(signer);
        wallet.withdraw(address(0), 1 ether, payable(user10));

        // Verify that the recipient received Ether
        assertEq(user10.balance, 1 ether, "Recipient should have received 1 ether");

        // Verify that Wallet balance decreased
        assertEq(address(wallet).balance, 9 ether, "Wallet balance should decrease by 1 ether");
    }

    /// @notice Test that withdraw function reverts when called by non-signer
    function testWithdraw_AsNonSigner_Revert() public {
        // Prank as non-signer and attempt to call withdraw
        vm.prank(nonSigner);
        vm.expectRevert("Not authorized");
        wallet.withdraw(address(0), 1 ether, payable(address(this)));
    }

    /// @notice Test that withdraw function works correctly for ERC20 tokens when called by signer
    function testWithdraw_Token_Success() public {
        // Deploy a mock ERC20 token
        MockERC20 token = new MockERC20("MockToken", "MTK", 18);
        token.mint(address(wallet), 1000 * 1e18);

        // Prank as signer and call withdraw
        vm.prank(signer);
        wallet.withdraw(address(token), 500 * 1e18, payable(address(this)));

        // Verify that the recipient received tokens
        assertEq(token.balanceOf(address(this)), 500 * 1e18, "Recipient should have received 500 MTK");

        // Verify that Wallet token balance decreased
        assertEq(token.balanceOf(address(wallet)), 500 * 1e18, "Wallet token balance should decrease by 500 MTK");
    }

    /// @notice Test that withdraw function reverts when called by non-signer for tokens
    function testWithdraw_Token_AsNonSigner_Revert() public {
        // Deploy a mock ERC20 token
        MockERC20 token = new MockERC20("MockToken", "MTK", 18);
        token.mint(address(wallet), 1000 * 1e18);

        // Prank as non-signer and attempt to call withdraw
        vm.prank(nonSigner);
        vm.expectRevert("Not authorized");
        wallet.withdraw(address(token), 500 * 1e18, payable(address(this)));
    }

    /// @notice Test that setRelayer can be called by signer to update relayer
    function testSetRelayer_AsSigner_Success() public {
        address newRelayer = address(0xA);

        // Expect RelayerChanged event
        vm.expectEmit(true, true, false, true);
        emit Wallet.RelayerChanged(relayer, newRelayer);

        // Prank as signer and call setRelayer
        vm.prank(signer);
        wallet.setRelayer(newRelayer);

        // Verify relayer is updated
        assertEq(wallet.relayer(), newRelayer, "Relayer should be updated to newRelayer");
    }

    /// @notice Test that setRelayer cannot be called by non-signer
    function testSetRelayer_AsNonSigner_Revert() public {
        address newRelayer = address(0xA);

        // Prank as non-signer and attempt to call setRelayer
        vm.prank(nonSigner);
        vm.expectRevert("Not authorized");
        wallet.setRelayer(newRelayer);
    }

    /// @notice Test that setRelayer cannot set to zero address
    function testSetRelayer_ToZeroAddress_Revert() public {
        address newRelayer = address(0);

        // Prank as signer and attempt to set relayer to zero address
        vm.prank(signer);
        vm.expectRevert("Invalid address");
        wallet.setRelayer(newRelayer);
    }

    /// @notice Test that withdraw Ether reverts if Wallet has insufficient balance
    function testWithdraw_Ether_InsufficientBalance_Revert() public {
        // Prank as signer and attempt to withdraw more Ether than available
        vm.prank(signer);
        vm.expectRevert("Insufficient balance");
        wallet.withdraw(address(0), 20 ether, payable(address(this)));
    }

    /// @notice Test that withdraw Token reverts if Wallet has insufficient token balance
    function testWithdraw_Token_InsufficientBalance_Revert() public {
        // Deploy a mock ERC20 token
        MockERC20 token = new MockERC20("MockToken", "MTK", 18);
        token.mint(address(wallet), 1000 * 1e18);

        // Prank as signer and attempt to withdraw more tokens than available
        vm.prank(signer);
        vm.expectRevert("Insufficient balance");
        wallet.withdraw(address(token), 1500 * 1e18, payable(address(this)));
    }

    /// @notice Test that executeAction reimburses relayer in tokens correctly
    function testExecuteAction_ReimburseInTokens_Success() public {
        // Deploy a mock ERC20 token
        MockERC20 token = new MockERC20("MockToken", "MTK", 18);
        token.mint(address(wallet), 1000 * 1e18);

        // Prepare action parameters
        address to = targetContract;
        uint256 value = 0; // No Ether transfer
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: false,
            tokenRate: 100 * 1e18, // 100 tokens per wei
            token: address(token)
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Record relayer token balance before
        uint256 relayerBalanceBefore = token.balanceOf(relayer);

        // Prank as relayer and call executeAction
        vm.prank(relayer);
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);

        // Record relayer token balance after
        uint256 relayerBalanceAfter = token.balanceOf(relayer);

        // Verify that relayer received the expected token amount
        assertGt(relayerBalanceAfter - relayerBalanceBefore, 0, "Relayer should have received token reimbursement");
    }

    /// @notice Test that executeAction reverts when token reimbursement fails due to insufficient token balance
    function testExecuteAction_ReimburseInTokens_InsufficientBalance_Revert() public {
        // Deploy a mock ERC20 token
        MockERC20 token = new MockERC20("MockToken", "MTK", 18);
        // Do not mint tokens to Wallet

        // Prepare action parameters
        address to = targetContract;
        uint256 value = 0; // No Ether transfer
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: false,
            tokenRate: 100 * 1e18, // 100 tokens per wei
            token: address(token)
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Prank as relayer and attempt to call executeAction
        vm.prank(relayer);
        vm.expectRevert("Insufficient token balance for gas reimbursement");
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
    }

    /// @notice Test that executeAction reimburses relayer in native tokens correctly when Wallet has insufficient balance
    function testExecuteAction_ReimburseInNative_InsufficientBalance_Revert() public {
        // Prepare action parameters
        address to = targetContract;
        uint256 value = 0; // No Ether transfer
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters with reimbursement higher than Wallet balance
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: true,
            tokenRate: 0,
            token: address(0)
        });

        vm.startPrank(signer);
        wallet.withdraw(address(0), 10 ether, payable(signer));
        vm.stopPrank();

        // Wallet has 10 ether initially, reimbursement is 100,000 * 100 gwei = 10,000,000 gwei = 10 ether
        // If we try to reimburse more than 10 ether, it should fail

        // Prepare gas reimbursement parameters with gasLimit * gasPrice = 11 ether
        gasParams.gasLimit = 110000; // 110,000 * 100 gwei = 11 ether

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Prank as relayer and attempt to call executeAction
        vm.prank(relayer);
        vm.expectRevert("Insufficient balance for gas reimbursement");
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
    }

    /// @notice Test that executeAction does not reimburse relayer when reimburse is false
    function testExecuteAction_NoReimbursement_Success() public {
        // Prepare action parameters
        address to = targetContract;
        uint256 value = 1 ether;
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters with reimburse = false
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: false,
            reimburseInNative: true, // Irrelevant since reimburse is false
            tokenRate: 0,
            token: address(0)
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Record relayer balance before
        uint256 relayerBalanceBefore = relayer.balance;

        // Prank as relayer and call executeAction
        vm.prank(relayer);
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);

        // Record relayer balance after
        uint256 relayerBalanceAfter = relayer.balance;

        // Verify relayer balance has not changed
        assertEq(relayerBalanceAfter, relayerBalanceBefore, "Relayer balance should not change");

        // Verify that targetContract received the Ether
        assertEq(targetContract.balance, 1 ether, "Target contract should have received 1 ether");
    }

    /// @notice Test that Wallet's domain separator is correct
    function testDomainSeparator() public {
        // Use the known name "Wallet" as it's hard-coded in the contract
        bytes32 expectedDomainSeparator = keccak256(
            abi.encode(
                wallet.DOMAIN_TYPEHASH(),
                keccak256(bytes("Wallet")),
                block.chainid,
                address(wallet)
            )
        );

        assertEq(wallet.DOMAIN_SEPARATOR(), expectedDomainSeparator, "Domain separator should be correct");
    }

    /// @notice Test that executeAction reverts when token address is invalid
    function testExecuteAction_InvalidTokenAddress_Revert() public {
        // Prepare action parameters
        address to = targetContract;
        uint256 value = 0; // No Ether transfer
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters with invalid token address
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: false,
            tokenRate: 100 * 1e18,
            token: address(0) // Invalid token address
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Prank as relayer and attempt to call executeAction
        vm.prank(relayer);
        vm.expectRevert("Invalid token address"); // Expecting "Invalid token address"
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
    }

    /// @notice Test that executeAction reverts when token reimbursement fails due to transfer failure
    function testExecuteAction_ReimburseInTokens_TransferFailure_Revert() public {
        // Deploy a malicious ERC20 token that always reverts on transfer
        MaliciousERC20 token = new MaliciousERC20("MaliciousToken", "MAL", 18);
        token.mint(address(wallet), 1000 * 1e18);

        // Prepare action parameters
        address to = targetContract;
        uint256 value = 0; // No Ether transfer
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: false,
            tokenRate: 100 * 1e18,
            token: address(token)
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Prank as relayer and attempt to call executeAction
        vm.prank(relayer);
        vm.expectRevert("Transfer failed");
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
    }

    /// @notice Test that executeAction can be called multiple times with correct nonces
    function testExecuteAction_MultipleCalls_Success() public {
        // Prepare first action
        address to1 = targetContract;
        uint256 value1 = 1 ether;
        bytes memory callData1 = abi.encodeWithSignature("foo()");
        uint256 _nonce1 = 0;

        Types.ReimburseGas memory gasParams1 = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: false,
            reimburseInNative: true,
            tokenRate: 0,
            token: address(0)
        });

        bytes memory signature1 = _signExecuteAction(to1, value1, callData1, _nonce1, gasParams1);

        // Expect ActionExecuted event
        vm.expectEmit(true, true, false, true);
        emit Wallet.ActionExecuted(to1, value1, callData1);

        // Prank as relayer and call executeAction first time
        vm.prank(relayer);
        wallet.executeAction{value: 0}(to1, value1, callData1, _nonce1, gasParams1, signature1);

        // Prepare second action
        address to2 = targetContract;
        uint256 value2 = 2 ether;
        bytes memory callData2 = abi.encodeWithSignature("bar()");
        uint256 _nonce2 = 1;

        Types.ReimburseGas memory gasParams2 = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: false,
            reimburseInNative: true,
            tokenRate: 0,
            token: address(0)
        });

        bytes memory signature2 = _signExecuteAction(to2, value2, callData2, _nonce2, gasParams2);

        // Expect ActionExecuted event
        vm.expectEmit(true, true, false, true);
        emit Wallet.ActionExecuted(to2, value2, callData2);

        // Prank as relayer and call executeAction second time
        vm.prank(relayer);
        wallet.executeAction{value: 0}(to2, value2, callData2, _nonce2, gasParams2, signature2);

        // Verify nonce is incremented correctly
        assertEq(wallet.nonce(), 2, "Nonce should be incremented correctly after multiple calls");

        // Verify that targetContract received both Ether transfers
        assertEq(targetContract.balance, 3 ether, "Target contract should have received total of 3 ether");
    }

    /// @notice Test that executeAction cannot be called multiple times with the same nonce
    function testExecuteAction_ReuseNonce_Revert() public {
        // Prepare action parameters
        address to = targetContract;
        uint256 value = 1 ether;
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: false,
            reimburseInNative: true,
            tokenRate: 0,
            token: address(0)
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Prank as relayer and call executeAction first time
        vm.prank(relayer);
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);

        // Attempt to reuse the same signature and nonce
        vm.prank(relayer);
        vm.expectRevert("Invalid nonce");
        wallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
    }
}

/// @title MockERC20
/// @notice A simple ERC20 token for testing purposes
contract MockERC20 is IERC20 {
    using SafeERC20 for IERC20;

    string public name;
    string public symbol;
    uint8 public decimals;

    uint256 public override totalSupply;

    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external override returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Allowance exceeded");

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

/// @title MaliciousERC20
/// @notice An ERC20 token that always reverts on transfer for testing purposes
contract MaliciousERC20 is IERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;

    uint256 public override totalSupply;

    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external pure override returns (bool) {
        revert("Transfer failed");
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external override returns (bool) {
        revert("TransferFrom failed");
    }
}

/// @title MockTargetContract
/// @notice A mock contract with payable foo() and bar() functions for testing purposes
contract MockTargetContract {
    event FooCalled();

    // Make foo() payable to accept Ether
    function foo() external payable {
        emit FooCalled();
    }

    // Make bar() payable to accept Ether
    function bar() external payable {
        emit FooCalled(); // Reusing the same event for simplicity
    }
}
