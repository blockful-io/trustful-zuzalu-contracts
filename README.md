# Trustful Zuzalu Contracts

This is a custom Resolver implementation for the Ethereum Attestation Service (EAS).

The purpose of this contract is to hook from EAS the access control features to access the Zuzalu
dApp.

## Getting Started

Start by getting `foundryup` latest version and installing the dependencies:ssss

```sh
$ curl -L https://foundry.paradigm.xyz | bash
$ yarn
```

If this is your first time with Foundry, check out the
[installation](https://github.com/foundry-rs/foundry#installation) instructions.

### Clean

Delete the build artifacts and cache directories:

```sh
$ forge clean
```

### Compile

Compile the contracts:

```sh
$ forge build
```

### Test

Run the tests:

```sh
$ yarn test
```

## Deployment and Verify

First you need to export the following environment variables from `.env` in the terminal, then
deploy the Resolver contract:

```sh
export API_KEY_OPTIMISTIC_ETHERSCAN="YOUR_KEY"
export RPC_OP="YOU_RPC"
export PRIVATE_KEY="YOUR_PKEY"
$ yarn deploy
```

To verify the contract, you need to add the deployed Resolver address to the environment variables
and export it. Then run the verify script:

```sh
export ADDRESS_RESOLVER="DEPLOYED_ADDRESS"
$ yarn verify
```

## License

This project is licensed under MIT.
