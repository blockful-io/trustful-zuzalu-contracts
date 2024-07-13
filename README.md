# Trustful Zuzalu Contracts

This is a custom Resolver implementation for the Ethereum Attestation Service (EAS).

The purpose of this contract is to hook from EAS the access control features to access the Zuzalu
dApp.

## How to use it?

The Resolver contract is a custom implementation of the EAS Resolver interface. It allows Trustful
to access the access control features and verify the user's identity to operate the dApp.

**ROOT:** The ROOT role is the owner of the Resolver contract.

- It has the permisison to give Manager badges to other participants, or remove them.
- It has the permisison to add and remove roles from the contract outside the EAS scope.
- It has the permisison to register allowed actions to EAS schemas by providing the uid and the
  action ID. This is how the resolver knows which action is being requested by the attestation.
  **NOTICE: This will dratiscally influence the behavior of the dApp, only configure if you know
  what you are doing.**

**MANAGER:** The MANAGER handler of checkin/checkout operations in the dApp.

- It has the permission to checkin participants.
- It has the permission to checkout participants.
- It has the permisison to give Manager badges to other participants, or remove them.
- It has the permission to set allowed titles to be used in attestations. During ZuVillage, badges
  have titles and comments, and the titles are fixed and defined by the event organizers. We need
  this to validate that the attestation follows the standards. the user can give to others in the
  dApp context.

**VILLAGER:** The VILLAGER role is for the event participant.

- It has the permission to give badges to other participants.
- It has the permission provide responses to badges received.
- It has the permission to checkout of the dApp.

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
