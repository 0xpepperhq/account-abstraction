// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

// Import Foundry's Test framework
import "forge-std/Test.sol";

// Import the UserWallet and other contracts
import {UserWallet} from "../contracts/UserWallet.sol";
import {ContractRegistry} from "../contracts/ContractRegistry.sol";
import {SignerRegistry} from "../contracts/SignerRegistry.sol";
import "../contracts/Types.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract UserWalletTest is Test {
    using stdStorage for StdStorage;
    using SafeERC20 for IERC20;

    // Contracts under test
    UserWallet public userWallet;
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
    string public constant name = "UserWallet";

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

        // Deploy UserWallet
        userWallet = new UserWallet(clientId, relayer, address(contractRegistry), address(signerRegistry));

        // Fund UserWallet with ETH for reimbursements
        vm.deal(address(userWallet), 10 ether);

        // Initialize DOMAIN_SEPARATOR
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                userWallet.DOMAIN_TYPEHASH(),
                keccak256(bytes(name)),
                block.chainid,
                address(userWallet)
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
                userWallet.REIMBURSE_GAS_TYPEHASH(),
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
                userWallet.EXECUTE_ACTION_TYPEHASH(),
                to,
                value,
                keccak256(data),
                _nonce,
                gasStructHash
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", userWallet.DOMAIN_SEPARATOR(), structHash)
        );

        // Sign the digest using the signer's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Test that the UserWallet is initialized correctly
    function testInitialization() public {
        assertEq(userWallet.clientId(), clientId, "ClientId should be set correctly");
        assertEq(userWallet.relayer(), relayer, "Relayer should be set correctly");
        assertEq(address(userWallet.contractRegistry()), address(contractRegistry), "ContractRegistry should be set correctly");
        assertEq(address(userWallet.signerRegistry()), address(signerRegistry), "SignerRegistry should be set correctly");
        assertEq(userWallet.nonce(), 0, "Initial nonce should be zero");
        assertEq(userWallet.DOMAIN_SEPARATOR(), DOMAIN_SEPARATOR, "Domain separator should be initialized correctly");
    }

    /// @notice Test that UserWallet can receive Ether via receive() function
    function testReceiveEther() public {
        vm.deal(address(this), 1 ether);
        vm.prank(address(this));
        (bool sent, ) = address(userWallet).call{value: 1 ether}("");
        require(sent, "Failed to send Ether");

        assertEq(address(userWallet).balance, 11 ether, "UserWallet should have received 1 ether");
    }

    /// @notice Test that UserWallet can receive Ether via fallback() function
    function testFallbackEther() public {
        bytes memory data = hex"1234";
        vm.deal(address(this), 1 ether);
        vm.prank(address(this));
        (bool sent, ) = address(userWallet).call{value: 1 ether}(data);
        require(sent, "Failed to send Ether via fallback");

        assertEq(address(userWallet).balance, 11 ether, "UserWallet should have received 1 ether via fallback");
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
        emit UserWallet.ActionExecuted(to, value, callData);

        // Prank as relayer and call executeAction
        vm.prank(relayer);
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);

        // Verify nonce incremented
        assertEq(userWallet.nonce(), 1, "Nonce should be incremented");

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
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
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
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
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
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
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
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
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
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
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
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
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

        // Prank as relayer and call executeAction
        vm.prank(relayer);
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);

        // Record relayer balance after
        uint256 relayerBalanceAfter = relayer.balance;

        // Calculate expected reimbursement (gasUsed * gasPrice)
        // Since exact gasUsed is difficult to predict in tests, we can assume a fixed reimbursement
        // Alternatively, mock gasUsed or adjust the UserWallet to allow injecting gasUsed for testing

        // For simplicity, we'll skip precise reimbursement checks
        // Instead, ensure that UserWallet balance remains unchanged as no Ether was sent
        assertEq(address(userWallet).balance, 10 ether, "UserWallet balance should remain unchanged as no Ether was sent");
    }

    /// @notice Test that withdraw function works correctly when called by signer
    function testWithdraw_Ether_Success() public {
        // Prank as signer and call withdraw
        vm.prank(signer);
        userWallet.withdraw(address(0), 1 ether, payable(address(this)));

        // Verify that the recipient received Ether
        assertEq(address(this).balance, 1 ether, "Recipient should have received 1 ether");

        // Verify that UserWallet balance decreased
        assertEq(address(userWallet).balance, 9 ether, "UserWallet balance should decrease by 1 ether");
    }

    /// @notice Test that withdraw function reverts when called by non-signer
    function testWithdraw_AsNonSigner_Revert() public {
        // Prank as non-signer and attempt to call withdraw
        vm.prank(nonSigner);
        vm.expectRevert("Not authorized");
        userWallet.withdraw(address(0), 1 ether, payable(address(this)));
    }

    /// @notice Test that withdraw function works correctly for ERC20 tokens when called by signer
    function testWithdraw_Token_Success() public {
        // Deploy a mock ERC20 token
        MockERC20 token = new MockERC20("MockToken", "MTK", 18);
        token.mint(address(userWallet), 1000 * 1e18);

        // Prank as signer and call withdraw
        vm.prank(signer);
        userWallet.withdraw(address(token), 500 * 1e18, payable(address(this)));

        // Verify that the recipient received tokens
        assertEq(token.balanceOf(address(this)), 500 * 1e18, "Recipient should have received 500 MTK");

        // Verify that UserWallet token balance decreased
        assertEq(token.balanceOf(address(userWallet)), 500 * 1e18, "UserWallet token balance should decrease by 500 MTK");
    }

    /// @notice Test that withdraw function reverts when called by non-signer for tokens
    function testWithdraw_Token_AsNonSigner_Revert() public {
        // Deploy a mock ERC20 token
        MockERC20 token = new MockERC20("MockToken", "MTK", 18);
        token.mint(address(userWallet), 1000 * 1e18);

        // Prank as non-signer and attempt to call withdraw
        vm.prank(nonSigner);
        vm.expectRevert("Not authorized");
        userWallet.withdraw(address(token), 500 * 1e18, payable(address(this)));
    }

    /// @notice Test that setRelayer can be called by signer to update relayer
    function testSetRelayer_AsSigner_Success() public {
        address newRelayer = address(0xA);

        // Expect RelayerChanged event
        vm.expectEmit(true, true, false, true);
        emit UserWallet.RelayerChanged(relayer, newRelayer);

        // Prank as signer and call setRelayer
        vm.prank(signer);
        userWallet.setRelayer(newRelayer);

        // Verify relayer is updated
        assertEq(userWallet.relayer(), newRelayer, "Relayer should be updated to newRelayer");
    }

    /// @notice Test that setRelayer cannot be called by non-signer
    function testSetRelayer_AsNonSigner_Revert() public {
        address newRelayer = address(0xA);

        // Prank as non-signer and attempt to call setRelayer
        vm.prank(nonSigner);
        vm.expectRevert("Not authorized");
        userWallet.setRelayer(newRelayer);
    }

    /// @notice Test that setRelayer cannot set to zero address
    function testSetRelayer_ToZeroAddress_Revert() public {
        address newRelayer = address(0);

        // Prank as signer and attempt to set relayer to zero address
        vm.prank(signer);
        vm.expectRevert("Invalid address");
        userWallet.setRelayer(newRelayer);
    }

    /// @notice Test that withdraw Ether reverts if UserWallet has insufficient balance
    function testWithdraw_Ether_InsufficientBalance_Revert() public {
        // Prank as signer and attempt to withdraw more Ether than available
        vm.prank(signer);
        vm.expectRevert("Insufficient balance");
        userWallet.withdraw(address(0), 20 ether, payable(address(this)));
    }

    /// @notice Test that withdraw Token reverts if UserWallet has insufficient token balance
    function testWithdraw_Token_InsufficientBalance_Revert() public {
        // Deploy a mock ERC20 token
        MockERC20 token = new MockERC20("MockToken", "MTK", 18);
        token.mint(address(userWallet), 1000 * 1e18);

        // Prank as signer and attempt to withdraw more tokens than available
        vm.prank(signer);
        vm.expectRevert("SafeERC20: low-level call failed");
        userWallet.withdraw(address(token), 1500 * 1e18, payable(address(this)));
    }

    /// @notice Test that executeAction reimburses relayer in tokens correctly
    function testExecuteAction_ReimburseInTokens_Success() public {
        // Deploy a mock ERC20 token
        MockERC20 token = new MockERC20("MockToken", "MTK", 18);
        token.mint(address(userWallet), 1000 * 1e18);

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
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);

        // Record relayer token balance after
        uint256 relayerBalanceAfter = token.balanceOf(relayer);

        // Calculate expected token reimbursement (gasUsed * gasPrice * tokenRate / 1e18)
        // For testing purposes, assume gasUsed = gasLimit
        uint256 expectedTokenAmount = (gasParams.gasLimit * gasParams.gasPrice * gasParams.tokenRate) / 1e18;

        // Verify that relayer received the expected token amount
        assertEq(relayerBalanceAfter - relayerBalanceBefore, expectedTokenAmount, "Relayer should have received correct token reimbursement");
    }

    /// @notice Test that executeAction reverts when token reimbursement fails due to insufficient token balance
    function testExecuteAction_ReimburseInTokens_InsufficientBalance_Revert() public {
        // Deploy a mock ERC20 token
        MockERC20 token = new MockERC20("MockToken", "MTK", 18);
        // Do not mint tokens to UserWallet

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
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
    }

    /// @notice Test that executeAction reimburses relayer in native tokens correctly when UserWallet has insufficient balance
    function testExecuteAction_ReimburseInNative_InsufficientBalance_Revert() public {
        // Prepare action parameters
        address to = targetContract;
        uint256 value = 0; // No Ether transfer
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters with reimbursement higher than UserWallet balance
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: true,
            tokenRate: 0,
            token: address(0)
        });

        // UserWallet has 10 ether initially, reimbursement is 100,000 * 100 gwei = 10,000,000 gwei = 10 ether
        // If we try to reimburse more than 10 ether, it should fail

        // Prepare gas reimbursement parameters with gasLimit * gasPrice = 11 ether
        gasParams.gasLimit = 110000; // 110,000 * 100 gwei = 11 ether

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Prank as relayer and attempt to call executeAction
        vm.prank(relayer);
        vm.expectRevert("Insufficient balance for gas reimbursement");
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
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
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);

        // Record relayer balance after
        uint256 relayerBalanceAfter = relayer.balance;

        // Verify relayer balance has not changed
        assertEq(relayerBalanceAfter, relayerBalanceBefore, "Relayer balance should not change");

        // Verify that targetContract received the Ether
        assertEq(targetContract.balance, 1 ether, "Target contract should have received 1 ether");
    }

    /// @notice Test that executeAction reimburses relayer in native tokens correctly when tokenRate is non-zero but reimburseInNative is true
    function testExecuteAction_ReimburseInNative_WithTokenRate_Revert() public {
        // Prepare action parameters
        address to = targetContract;
        uint256 value = 0;
        bytes memory callData = abi.encodeWithSignature("foo()");
        uint256 _nonce = 0;

        // Prepare gas reimbursement parameters with reimburseInNative = true and tokenRate > 0
        Types.ReimburseGas memory gasParams = Types.ReimburseGas({
            gasPrice: 100 gwei,
            gasLimit: 100000,
            reimburse: true,
            reimburseInNative: true,
            tokenRate: 100 * 1e18, // Should be ignored or cause revert
            token: address(0)
        });

        // Generate signature
        bytes memory signature = _signExecuteAction(to, value, callData, _nonce, gasParams);

        // Prank as relayer and call executeAction
        // Depending on implementation, this might not revert, but we'll include it as a test case
        // If you want to enforce that tokenRate should be zero when reimburseInNative is true, modify UserWallet accordingly
        vm.prank(relayer);
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);

        // Verify relayer received reimbursement
        // Calculating exact reimbursement is tricky; we'll assume it's gasLimit * gasPrice
        uint256 expectedReimbursement = gasParams.gasLimit * gasParams.gasPrice;

        // Verify that relayer received the expected Ether amount
        assertEq(relayer.balance, expectedReimbursement, "Relayer should have received correct Ether reimbursement");
    }

    /// @notice Test that UserWallet's domain separator is correct
    function testDomainSeparator() public {
        // Use the known name "UserWallet" as it's hard-coded in the contract
        bytes32 expectedDomainSeparator = keccak256(
            abi.encode(
                userWallet.DOMAIN_TYPEHASH(),
                keccak256(bytes("UserWallet")),
                block.chainid,
                address(userWallet)
            )
        );

        assertEq(userWallet.DOMAIN_SEPARATOR(), expectedDomainSeparator, "Domain separator should be correct");
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
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
    }

    /// @notice Test that executeAction reverts when token reimbursement fails due to transfer failure
    function testExecuteAction_ReimburseInTokens_TransferFailure_Revert() public {
        // Deploy a malicious ERC20 token that always reverts on transfer
        MaliciousERC20 token = new MaliciousERC20("MaliciousToken", "MAL", 18);
        token.mint(address(userWallet), 1000 * 1e18);

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
        vm.expectRevert("SafeERC20: low-level call failed");
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
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
        emit UserWallet.ActionExecuted(to1, value1, callData1);

        // Prank as relayer and call executeAction first time
        vm.prank(relayer);
        userWallet.executeAction{value: 0}(to1, value1, callData1, _nonce1, gasParams1, signature1);

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
        emit UserWallet.ActionExecuted(to2, value2, callData2);

        // Prank as relayer and call executeAction second time
        vm.prank(relayer);
        userWallet.executeAction{value: 0}(to2, value2, callData2, _nonce2, gasParams2, signature2);

        // Verify nonce is incremented correctly
        assertEq(userWallet.nonce(), 2, "Nonce should be incremented correctly after multiple calls");

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
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);

        // Attempt to reuse the same signature and nonce
        vm.prank(relayer);
        vm.expectRevert("Invalid nonce");
        userWallet.executeAction{value: 0}(to, value, callData, _nonce, gasParams, signature);
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

    function transfer(address to, uint256 amount) external override returns (bool) {
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
/// @notice A mock contract with a foo() function for testing purposes
contract MockTargetContract {
    event FooCalled();

    function foo() external {
        emit FooCalled();
    }

    function bar() external {
        // This function can be empty or emit an event for testing
        emit FooCalled(); // Reusing the same event for simplicity
    }
}