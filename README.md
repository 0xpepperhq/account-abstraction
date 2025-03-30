# Account Abstraction System

A robust and upgradeable Account Abstraction system that enables smart contract wallets with advanced features like gas abstraction and signature verification.

## Overview

This project implements an Account Abstraction system that allows for:
- Creation and management of smart contract wallets
- Gas abstraction through dedicated gas stations
- Signature verification and validation
- Client-specific wallet and gas station management
- Upgradeable contracts using UUPS pattern
- Deterministic contract deployment using CREATE3

## Features

- **Smart Contract Wallets**
  - Deterministic address generation
  - Signature verification
  - Transaction execution
  - Client-specific functionality

- **Gas Abstraction**
  - Dedicated gas stations
  - Relayer integration
  - Client-specific gas policies

- **Registry System**
  - Signer management
  - Contract whitelisting
  - Client-specific permissions

- **Security**
  - Access control
  - Signature verification
  - Gas protection
  - Upgradeable contracts

## Prerequisites

- Solidity ^0.8.17
- Foundry
- OpenZeppelin Contracts
- Node.js (for development)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/account-abstraction.git
cd account-abstraction
```

2. Install dependencies:
```bash
forge install
```

3. Build the project:
```bash
forge build
```

## Project Structure

```
├── contracts/
│   ├── Wallet.sol              # Smart contract wallet implementation
│   ├── WalletFactory.sol       # Wallet creation and management
│   ├── GasStation.sol          # Gas abstraction implementation
│   ├── GasStationFactory.sol   # Gas station creation and management
│   ├── SignerRegistry.sol      # Signer management
│   ├── ContractRegistry.sol    # Contract whitelisting
│   ├── SignatureHelper.sol     # Signature verification
│   ├── utils/                  # Utility contracts
│   └── interfaces/             # Contract interfaces
├── test/                       # Test files
├── script/                     # Deployment scripts
└── lib/                        # Dependencies
```

## Usage

### Creating a Wallet

```solidity
// 1. Register a signer
signerRegistry.registerSigner(clientId, signerAddress);

// 2. Create a wallet
walletFactory.createWallet(userId, clientId);
```

### Managing Gas Stations

```solidity
// 1. Create a gas station
gasStationFactory.createGasStation(clientId);

// 2. Use gas station for transactions
gasStation.executeTransaction(transaction);
```

### Upgrading Contracts

```solidity
// 1. Deploy new implementation
NewImplementation newImpl = new NewImplementation();

// 2. Upgrade through proxy
proxy.upgradeTo(address(newImpl));
```

## Testing

Run the test suite:
```bash
forge test
```

Run tests with verbosity:
```bash
forge test -vv
```

## Deployment

1. Deploy core registries:
```bash
forge script script/Deployer.s.sol:DeployerTest --rpc-url <RPC_URL> --broadcast
```

2. Verify contracts:
```bash
forge verify-contract <ADDRESS> <CONTRACT_NAME> --chain-id <CHAIN_ID>
```

## Security

- All contracts are upgradeable using the UUPS pattern
- Access control is implemented for all critical functions
- Signature verification follows EIP-712 standard
- Gas protection mechanisms are in place
- Regular security audits are recommended

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- OpenZeppelin for the upgradeable contracts pattern
- Solmate for the CREATE3 implementation
- The Ethereum community for Account Abstraction standards
