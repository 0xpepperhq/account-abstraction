// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IContractRegistry {
    function isContractAllowed(bytes32 _clientId, address _contract) external view returns (bool);
}

interface ISignerRegistry {
    function getSigner(bytes32 clientId) external view returns (address signer);
}

contract UserWallet is ReentrancyGuard {
    using SafeERC20 for IERC20;

    bytes32 public clientId;
    address public relayer;

    // Initialization flag
    bool private initialized;

    // Reference to the ContractRegistry
    IContractRegistry public contractRegistry;

    // Reference to the SignerRegistry
    ISignerRegistry public signerRegistry;

    // Nonce to prevent replay attacks
    uint256 public nonce;

    // EIP-712 Domain Separator and TypeHashes
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant REIMBURSE_GAS_TYPEHASH = keccak256(
        "ReimburseGas(uint256 gasPrice,uint256 gasLimit,bool reimburse,bool reimburseInNative,uint256 tokenRate,address token)"
    );
    bytes32 public constant EXECUTE_ACTION_TYPEHASH = keccak256(
        "ExecuteAction(address to,uint256 value,bytes data,uint256 nonce,ReimburseGas gas)ReimburseGas(uint256 gasPrice,uint256 gasLimit,bool reimburse,bool reimburseInNative,uint256 tokenRate,address token)"
    );
    bytes32 public DOMAIN_SEPARATOR;

    struct ReimburseGas {
        uint256 gasPrice;
        uint256 gasLimit;
        bool reimburse;
        bool reimburseInNative;
        uint256 tokenRate; // Tokens per wei (scaled by 1e18)
        address token;
    }

    // Events
    event Deposited(address indexed token, uint256 amount);
    event Withdrawn(address indexed token, uint256 amount);
    event ActionExecuted(address indexed to, uint256 value, bytes data);
    event RelayerChanged(address indexed oldRelayer, address indexed newRelayer);
    event ContractRegistryChanged(address indexed oldRegistry, address indexed newRegistry);

    modifier onlyRelayer() {
        require(msg.sender == relayer, "Not authorized");
        _;
    }

    modifier onlyAllowedContract(address _contract) {
        require(contractRegistry.isContractAllowed(clientId, _contract), "Contract not allowed");
        _;
    }

    modifier onlySigner() {
        require(msg.sender == signerRegistry.getSigner(clientId), "Not authorized");
        _;
    }

    /// @notice Constructor
    /// @param _clientId The client ID of the wallet
    /// @param _relayer The relayer address
    /// @param _contractRegistry The address of the ContractRegistry
    constructor(
        bytes32 _clientId,
        address _relayer,
        address _contractRegistry
    ) {
        address signer = signerRegistry.getSigner(_clientId);

        require(signer != address(0), "Invalid signer address");
        require(_relayer != address(0), "Invalid relayer address");
        require(_contractRegistry != address(0), "Invalid contract registry address");

        clientId = _clientId;
        relayer = _relayer;
        contractRegistry = IContractRegistry(_contractRegistry);

        // Initialize EIP-712 Domain Separator
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("UserWallet")),
                block.chainid,
                address(this)
            )
        );
    }

    // Accept Ether deposits
    receive() external payable {
        emit Deposited(address(0), msg.value);
    }

    // Fallback function
    fallback() external payable {
        emit Deposited(address(0), msg.value);
    }

    /// @notice Execute an action on behalf of the user
    /// @param to The target contract address
    /// @param value The amount of Ether to send with the call
    /// @param data The calldata to execute
    /// @param _nonce The user's nonce to prevent replay attacks
    /// @param gas The gas reimbursement parameters
    /// @param signature The user's signature authorizing the action
    function executeAction(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 _nonce,
        ReimburseGas calldata gas,
        bytes calldata signature
    ) external payable onlyRelayer onlyAllowedContract(to) nonReentrant {
        // Record the initial gas
        uint256 initialGas = gasleft();
        address signer = signerRegistry.getSigner(clientId);

        // Validate nonce
        require(_nonce == nonce, "Invalid nonce");
        nonce++;

        // Validate gas parameters
        uint256 MAX_GAS_PRICE = 200 gwei;
        uint256 MAX_GAS_LIMIT = 500000;
        require(gas.gasPrice <= MAX_GAS_PRICE, "Gas price too high");
        require(gas.gasLimit <= MAX_GAS_LIMIT, "Gas limit too high");

        // Verify the user's signature
        bytes32 messageHash = getMessageHash(to, value, data, _nonce, gas);
        require(
            verifySignature(signer, messageHash, signature),
            "Invalid signature"
        );

        // Execute the action
        (bool success, ) = to.call{value: value}(data);
        require(success, "Action execution failed");

        // Calculate gas used, including the gas overhead
        uint256 gasOverhead = 21000 + 10000; // Adjusted overhead
        uint256 gasUsed = initialGas - gasleft() + gasOverhead;
        uint256 gasCost = gasUsed * gas.gasPrice;

        // Reimburse the relayer
        if (gas.reimburse) {
            if (gas.reimburseInNative) {
                require(address(this).balance >= gasCost, "Insufficient balance for gas reimbursement");
                (bool reimbursementSuccess, ) = payable(relayer).call{value: gasCost}("");
                require(reimbursementSuccess, "Gas reimbursement failed");
            } else {
                require(gas.token != address(0), "Invalid token address");
                // tokenRate is tokens per wei, scaled by 1e18
                uint256 tokenAmount = (gasCost * gas.tokenRate) / 1e18;
                require(IERC20(gas.token).balanceOf(address(this)) >= tokenAmount, "Insufficient token balance for gas reimbursement");
                IERC20(gas.token).safeTransfer(relayer, tokenAmount);
            }
        }

        emit ActionExecuted(to, value, data);
    }

    /// @notice Allows the user to withdraw tokens
    /// @param token The token address (use address(0) for Ether)
    /// @param amount The amount to withdraw
    /// @param to The address to send the funds to
    function withdraw(
        address token,
        uint256 amount,
        address payable to
    ) external nonReentrant onlySigner {
        if (token == address(0)) {
            require(address(this).balance >= amount, "Insufficient balance");
            (bool success, ) = to.call{value: amount}("");
            require(success, "Ether transfer failed");
        } else {
            IERC20(token).safeTransfer(to, amount);
        }

        emit Withdrawn(token, amount);
    }

    /// @notice Generates the message hash for signature verification using EIP-712
    /// @param to The target contract address
    /// @param value The amount of Ether to send with the call
    /// @param data The calldata to execute
    /// @param _nonce The user's nonce
    /// @param gas The gas reimbursement parameters
    function getMessageHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 _nonce,
        ReimburseGas calldata gas
    ) public view returns (bytes32) {
        bytes32 gasStructHash = keccak256(
            abi.encode(
                REIMBURSE_GAS_TYPEHASH,
                gas.gasPrice,
                gas.gasLimit,
                gas.reimburse,
                gas.reimburseInNative,
                gas.tokenRate,
                gas.token
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTE_ACTION_TYPEHASH,
                to,
                value,
                keccak256(data),
                _nonce,
                gasStructHash
            )
        );

        return
            keccak256(
                abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
            );
    }

    /// @notice Verifies the signature using EIP-712
    /// @param signer The signer's address
    /// @param messageHash The hash to sign
    /// @param signature The signature
    function verifySignature(
        address signer,
        bytes32 messageHash,
        bytes calldata signature
    ) public pure returns (bool) {
        require(signature.length == 65, "Invalid signature length");

        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);

        // Check if s-value is in the lower half order
        require(
            uint256(s) <=
                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
            "Invalid s value"
        );

        // Check if v is 27 or 28
        require(v == 27 || v == 28, "Invalid v value");

        address recoveredSigner = ecrecover(messageHash, v, r, s);
        return recoveredSigner == signer;
    }

    /// @notice Splits the signature into r, s, and v components
    /// @param sig The signature
    function splitSignature(bytes calldata sig)
        public
        pure
        returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(sig.length == 65, "Invalid signature length");

        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
    }

    /// @notice Allows the signer to change the relayer
    /// @param _newRelayer The new relayer address
    function setRelayer(address _newRelayer) external onlySigner {
        require(_newRelayer != address(0), "Invalid address");
        emit RelayerChanged(relayer, _newRelayer);
        relayer = _newRelayer;
    }
}
