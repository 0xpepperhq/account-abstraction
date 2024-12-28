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

$ forge verify-contract 0x7872dd74E22b58070902D16991E9CF1C7338258D contracts/WalletFactory.sol:WalletFactory --constructor-args $(cast abi-encode "constructor(address,address,address,address)" 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722 0x6F6623B00B0b2eAEFA47A4fDE06d6931F7121722 0x75C4A34B13a891679241A34bEfA3c5a83bFE032a 0x5a684137fddb5dFF6e2276906BDbf0510F022FBc) --verifier blockscout --verifier-url https://sepolia-blockscout.lisk.com/api --chain 4202 --watch 
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
