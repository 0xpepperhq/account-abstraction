// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract SignerRegistry is ReentrancyGuard {
    address public admin;

    // Mapping of allowed contracts
    mapping(address => bool) private blocklistSigners;
    mapping(bytes32 => address) private signers;

    // Events
    event SignerRegistered(bytes32 indexed clientId, address signer);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor(address _admin) {
        require(_admin != address(0), "Invalid admin address");
        admin = _admin;
    }

    /// @notice Allows the admin register signers
    /// @param clientId The client ID
    /// @param signer The contract address to allow or disallow
    function registerSigner(bytes32 clientId, address signer) external onlyAdmin nonReentrant {
        signers[clientId] = signer;
        emit SignerRegistered(clientId, signer);
    }

    /// @notice Get the signer for a client ID
    /// @param clientId The client ID
    /// @return signer The signer address
    function getSigner(bytes32 clientId) external view returns (address signer) {
        signer = signers[clientId];
        require(signer != address(0), "Signer not found");
        require(!blocklistSigners[signer], "Signer is blocked");
    }

    /// @notice Allows the admin to block signers
    /// @param signer The signer address to block
    function blockSigner(address signer) external onlyAdmin nonReentrant {
        blocklistSigners[signer] = true;
    }

    /// @notice Allows the admin to change the admin address
    /// @param _newAdmin The new admin address
    function setAdmin(address _newAdmin) external onlyAdmin nonReentrant {
        require(_newAdmin != address(0), "Invalid admin address");
        emit AdminChanged(admin, _newAdmin);
        admin = _newAdmin;
    }
}
