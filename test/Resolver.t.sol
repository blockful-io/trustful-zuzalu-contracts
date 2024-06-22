// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Test, console2 } from "forge-std/src/Test.sol";
import { Resolver } from "../src/resolver/Resolver.sol";
import { IResolver } from "../src/interfaces/IResolver.sol";
import { ISchemaRegistry } from "../src/interfaces/ISchemaRegistry.sol";
import { IEAS } from "../src/interfaces/IEAS.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";

contract ResolverTest is Test {
  IEAS eas = IEAS(0x4200000000000000000000000000000000000021);
  ISchemaRegistry schemaRegistry = ISchemaRegistry(0x4200000000000000000000000000000000000020);
  IResolver resolver;

  bytes32 ROOT_ROLE = keccak256("ROOT_ROLE");
  bytes32 MANAGER_ROLE = keccak256("MANAGER_ROLE");
  bytes32 VILLAGER_ROLE = keccak256("VILLAGER_ROLE");

  address deployer = 0xF977814e90dA44bFA03b6295A0616a897441aceC;
  address roleReceiver = 0x96DB2c6D93A8a12089f7a6EdA5464e967308AdEd;

  function setUp() public {
    vm.label(deployer, "deployer");
    vm.label(roleReceiver, "roleReceiver");
    vm.startPrank(deployer);
    resolver = new Resolver(eas);
  }

  function test_access_control_add_attest_title() public returns (string[] memory) {
    string[] memory titles = new string[](3);
    titles[0] = "Changed My Mind";
    titles[1] = "Is a good person";
    titles[2] = "Has a brilliant mind";

    resolver.setAttestationTitle(titles[0], true);
    assert(resolver.allowedAttestationTitles(titles[0]));

    resolver.setAttestationTitle(titles[1], true);
    assert(resolver.allowedAttestationTitles(titles[1]));

    resolver.setAttestationTitle(titles[2], true);
    assert(resolver.allowedAttestationTitles(titles[2]));

    return titles;
  }

  function test_access_control_revoke_attest_title() public {
    string[] memory titles = test_access_control_add_attest_title();

    resolver.setAttestationTitle(titles[0], false);
    assert(!resolver.allowedAttestationTitles(titles[0]));

    resolver.setAttestationTitle(titles[1], false);
    assert(!resolver.allowedAttestationTitles(titles[1]));

    resolver.setAttestationTitle(titles[2], false);
    assert(!resolver.allowedAttestationTitles(titles[2]));
  }

  function test_access_control_add_schemas() public returns (bytes32[] memory) {
    bytes32[] memory uids = new bytes32[](4);

    /// ASSIGN MANAGER SCHEMA
    string memory schema = "";
    bool revocable = true;
    bytes32 uid = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uid, ROOT_ROLE, 1);
    assert(resolver.schemas(uid, ROOT_ROLE) == IResolver.Action.ASSIGN_MANAGER);
    uids[0] = uid;

    /// ASSIGN VILLAGER SCHEMA
    schema = "";
    revocable = false;
    uid = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uid, MANAGER_ROLE, 2);
    assert(resolver.schemas(uid, MANAGER_ROLE) == IResolver.Action.ASSIGN_VILLAGER);
    uids[1] = uid;

    /// Event Attestation SCHEMA
    schema = "string title, string comment";
    revocable = false;
    uid = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uid, VILLAGER_ROLE, 3);
    assert(resolver.schemas(uid, VILLAGER_ROLE) == IResolver.Action.ATTEST);
    uids[2] = uid;

    /// Event Response SCHEMA
    schema = "bool status";
    revocable = true;
    uid = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uid, VILLAGER_ROLE, 4);
    assert(resolver.schemas(uid, VILLAGER_ROLE) == IResolver.Action.REPLY);
    uids[3] = uid;

    return uids;
  }

  function test_access_control_revoke_schemas() public {
    bytes32[] memory uids = test_access_control_add_schemas();

    /// MANAGER SCHEMA
    resolver.setSchema(uids[0], ROOT_ROLE, 0);
    assert(resolver.schemas(uids[0], ROOT_ROLE) == IResolver.Action.NONE);

    /// VILLAGER SCHEMA
    resolver.setSchema(uids[1], MANAGER_ROLE, 0);
    assert(resolver.schemas(uids[1], MANAGER_ROLE) == IResolver.Action.NONE);

    /// Event Attestation SCHEMA
    resolver.setSchema(uids[2], VILLAGER_ROLE, 0);
    assert(resolver.schemas(uids[2], VILLAGER_ROLE) == IResolver.Action.NONE);

    /// Event Response SCHEMA
    resolver.setSchema(uids[3], VILLAGER_ROLE, 0);
    assert(resolver.schemas(uids[3], VILLAGER_ROLE) == IResolver.Action.NONE);
  }

  function test_access_control_create_roles() public {
    // Should not have the manager role at first
    assert(!hasRole(MANAGER_ROLE, roleReceiver));
    // Grant MANAGER_ROLE and check
    grantRole(MANAGER_ROLE, roleReceiver);
    assert(hasRole(MANAGER_ROLE, roleReceiver));
    // Should not have the villager at first
    assert(!hasRole(VILLAGER_ROLE, roleReceiver));
    // Grant VILLAGER_ROLE and check
    grantRole(VILLAGER_ROLE, roleReceiver);
    assert(hasRole(VILLAGER_ROLE, roleReceiver));
  }

  function test_access_control_revoke_roles() public {
    test_access_control_create_roles();

    assert(hasRole(MANAGER_ROLE, roleReceiver));
    revokeRole(MANAGER_ROLE, roleReceiver);
    assert(!hasRole(MANAGER_ROLE, roleReceiver));

    assert(hasRole(VILLAGER_ROLE, roleReceiver));
    revokeRole(VILLAGER_ROLE, roleReceiver);
    assert(!hasRole(VILLAGER_ROLE, roleReceiver));

    assert(hasRole(ROOT_ROLE, deployer));
    revokeRole(ROOT_ROLE, deployer);
    assert(!hasRole(ROOT_ROLE, deployer));
  }

  function hasRole(bytes32 role, address account) public view returns (bool) {
    return IAccessControl(address(resolver)).hasRole(role, account);
  }

  function grantRole(bytes32 role, address account) public {
    IAccessControl(address(resolver)).grantRole(role, account);
  }

  function revokeRole(bytes32 role, address account) public {
    IAccessControl(address(resolver)).revokeRole(role, account);
  }
}
