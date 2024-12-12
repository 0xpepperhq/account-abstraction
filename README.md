## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Deployer.s.sol:Deployer --broadcast --account pepper-deployer --rpc-url https://rpc.sepolia-api.lisk.com
$ forge verify-contract 0xB461E25623DFCC311C4eD11AD0163b6c9De0A266 contracts/WalletFactory.sol:WalletFactory --constructor-args $(cast abi-encode "constructor(address,address,address,address)" 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722 0x6C76a6B4137e6b1A554dAD212b46A40bBD72863B 0xbb3C288b261c5fbB83777181f6c321D1528E2960) --verifier blockscout --verifier-url https://sepolia-blockscout.lisk.com/api --chain 4202 --watch 
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
