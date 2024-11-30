// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./interfaces/ISignerRegistry.sol";

contract ContractRegistry is ReentrancyGuard {
    // Signer Registry
    ISignerRegistry public signerRegistry;

    // Mapping of allowed contracts
    mapping(bytes32 => mapping(address => bool)) private clientAllowedContracts;

    // Events
    event ContractAllowed(address indexed _contract, bool _allowed);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    modifier onlySigner(bytes32 _clientId) {
        require(signerRegistry.getSigner(_clientId) == msg.sender, "Not authorized");
        _;
    }

    constructor(address _signerRegistry) {
        require(_signerRegistry != address(0), "Invalid signerRegistry address");
        signerRegistry = ISignerRegistry(_signerRegistry);
    }

    /// @notice Allows the admin to set allowed contracts
    /// @param _contract The contract address to allow or disallow
    /// @param _allowed Boolean indicating whether the contract is allowed
    function setAllowedContract(bytes32 _clientId, address _contract, bool _allowed) external onlySigner(_clientId) nonReentrant {
        clientAllowedContracts[_clientId][_contract] = _allowed;
        emit ContractAllowed(_contract, _allowed);
    }

    /// @notice Checks if a contract is allowed
    /// @param _contract The contract address to check
    /// @return True if the contract is allowed, false otherwise
    function isContractAllowed(bytes32 _clientId, address _contract) external view returns (bool) {
        return clientAllowedContracts[_clientId][_contract];
    }
}
