// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import { Resolver } from "./Resolver.sol";
import { IEAS } from "../interfaces/IEAS.sol";
import { ISchemaRegistry } from "../interfaces/ISchemaRegistry.sol";
import { IResolver } from "../interfaces/IResolver.sol";
import { InvalidEAS, InvalidSchemaRegistry } from "../Common.sol";

/// @author 0xCucurbitacea
/// @notice Factory contract for deploying Resolver contracts
contract ResolverFactory {
    /// @notice Event emitted when a new Resolver is deployed
    event ResolverDeployed(address indexed resolver, address indexed deployer, bytes32[] schemaUIDs);

    /// @dev Deploys a new Resolver contract
    /// @param eas_ The address of the global EAS contract
    /// @param schemaRegistry_ The address of the schema registry
    /// @param managers_ Array of addresses that will receive the MANAGER_ROLE
    /// @return The address of the newly deployed Resolver
    function deployResolver(
        IEAS eas_,
        ISchemaRegistry schemaRegistry_,
        address[] memory managers_
    ) external returns (address) {
        if (address(eas_) == address(0)) revert InvalidEAS();
        if (address(schemaRegistry_) == address(0)) revert InvalidSchemaRegistry();

        Resolver resolver = new Resolver(eas_, schemaRegistry_, msg.sender, managers_);

        // Get all schema UIDs from the resolver
        bytes32[] memory schemaUIDs = new bytes32[](4);
        schemaUIDs[0] = IResolver(address(resolver)).getAllSchemas(IResolver.Action.ASSIGN_MANAGER)[0];
        schemaUIDs[1] = IResolver(address(resolver)).getAllSchemas(IResolver.Action.ASSIGN_VILLAGER)[0];
        schemaUIDs[2] = IResolver(address(resolver)).getAllSchemas(IResolver.Action.ATTEST)[0];
        schemaUIDs[3] = IResolver(address(resolver)).getAllSchemas(IResolver.Action.REPLY)[0];

        emit ResolverDeployed(address(resolver), msg.sender, schemaUIDs);

        return address(resolver);
    }
}
