// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Test, console2 } from "forge-std/src/Test.sol";
import { Resolver } from "../src/resolver/Resolver.sol";
import { ISchemaResolver } from "../src/interfaces/ISchemaResolver.sol";
import { ISchemaRegistry } from "../src/interfaces/ISchemaRegistry.sol";
import { IEAS } from "../src/interfaces/IEAS.sol";

contract RegistryTest is Test {
  IEAS eas = IEAS(0x4200000000000000000000000000000000000021);
  ISchemaRegistry schemaRegistry = ISchemaRegistry(0x4200000000000000000000000000000000000020);
  ISchemaResolver resolver;

  function setUp() public {
    vm.startPrank(0xF977814e90dA44bFA03b6295A0616a897441aceC);
    resolver = new Resolver(eas);
  }

  function test_registry_manager() public {
    string memory schema = "";
    bool revocable = true;

    bytes32 uid = schemaRegistry.register(schema, resolver, revocable);
    console2.log("Schema UID generated:");
    console2.logBytes32(uid);
  }
}
