// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

interface ISignerRegistry {
    function getSigner(bytes32 clientId) external view returns (address signer);
}

contract GasStation {
    address public admin;
    address public relayer;

    ISignerRegistry public signerRegistry;

    // Withdrawal limit per transaction (e.g., 0.01 ETH)
    uint256 public constant MAX_GAS_WITHDRAWAL = 0.01 ether;

    // Events
    event GasProvided(address indexed relayer, uint256 amount);
    event RelayerChanged(address indexed oldRelayer, address indexed newRelayer);
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    modifier onlySigner(bytes32 _clientId) {
        require(msg.sender == signerRegistry.getSigner(_clientId), "Not authorized");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    modifier onlyRelayer() {
        require(msg.sender == relayer, "Not authorized");
        _;
    }

    constructor(address _signerRegistry, address _admin, address _relayer) {
        require(_signerRegistry != address(0), "Invalid owner address");
        require(_admin != address(0), "Invalid admin address");
        require(_relayer != address(0), "Invalid relayer address");

        signerRegistry = ISignerRegistry(_signerRegistry);
        admin = _admin;
        relayer = _relayer;
    }

    /// @notice Provides gas funds to the relayer
    /// @param amount The amount of ETH to provide for gas
    function provideGas(uint256 amount) external onlyRelayer {
        require(amount <= MAX_GAS_WITHDRAWAL, "Exceeds max gas withdrawal limit");
        require(address(this).balance >= amount, "Insufficient gas station balance");

        // Transfer ETH to the relayer
        (bool success, ) = relayer.call{value: amount}("");
        require(success, "Gas transfer failed");

        emit GasProvided(relayer, amount);
    }

    /// @notice Allows the owner to change the relayer
    /// @param _newRelayer The new relayer address
    function setRelayer(address _newRelayer) external onlyAdmin {
        require(_newRelayer != address(0), "Invalid relayer address");
        emit RelayerChanged(relayer, _newRelayer);
        relayer = _newRelayer;
    }

    /// @notice Allows the owner to withdraw ETH from the contract
    /// @param amount The amount of ETH to withdraw
    function withdraw(bytes32 _clientId, uint256 amount) external onlySigner(_clientId) {
        address signer = signerRegistry.getSigner(_clientId);
    
        require(signer != address(0), "Invalid signer address");
        require(amount <= address(this).balance, "Insufficient balance");
    
        (bool success, ) = payable(signer).call{value: amount}("");
        require(success, "Withdrawal failed");
    }

    // Function to receive ETH deposits
    receive() external payable {}
}
