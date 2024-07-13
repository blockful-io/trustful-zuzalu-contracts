// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Test, console2 } from "forge-std/src/Test.sol";
import { Resolver } from "../src/resolver/Resolver.sol";
import { IResolver } from "../src/interfaces/IResolver.sol";
import { ISchemaRegistry } from "../src/interfaces/ISchemaRegistry.sol";
import { IEAS } from "../src/interfaces/IEAS.sol";

contract RegistryTest is Test {
  IEAS eas = IEAS(0x4200000000000000000000000000000000000021);
  ISchemaRegistry schemaRegistry = ISchemaRegistry(0x4200000000000000000000000000000000000020);
  IResolver resolver;

  function setUp() public {
    vm.startPrank(0xF977814e90dA44bFA03b6295A0616a897441aceC);
    resolver = new Resolver(eas);
  }

  function test_registry_manager() public {
    string memory schema = "string role";
    bool revocable = true;

    bytes32 uid = schemaRegistry.register(schema, resolver, revocable);
    console2.log("Schema UID generated Manager:");
    console2.logBytes32(uid);
  }

  function test_registry_villager() public {
    string memory schema = "string status";
    bool revocable = false;

    bytes32 uid = schemaRegistry.register(schema, resolver, revocable);
    console2.log("Schema UID generated Villager:");
    console2.logBytes32(uid);
  }

  function test_registry_attest() public {
    string memory schema = "string title,string comment";
    bool revocable = false;

    bytes32 uid = schemaRegistry.register(schema, resolver, revocable);

    console2.log("Schema UID generated attest:");
    console2.logBytes32(uid);
  }

  function test_registry_response_attest() public {
    string memory schema = "bool status";
    bool revocable = true;

    bytes32 uid = schemaRegistry.register(schema, resolver, revocable);

    console2.log("Schema UID generated Response attest:");
    console2.logBytes32(uid);
  }
}
