// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Test, console2 } from "forge-std/src/Test.sol";
import { Resolver } from "../src/resolver/Resolver.sol";
import { IResolver } from "../src/interfaces/IResolver.sol";
import { ISchemaRegistry } from "../src/interfaces/ISchemaRegistry.sol";
import { IEAS } from "../src/interfaces/IEAS.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { ResolverFactory } from "../src/resolver/ResolverFactory.sol";

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
    ResolverFactory resolverFactory = new ResolverFactory();
    resolver = IResolver(resolverFactory.deployResolver(eas, schemaRegistry, new address[](0)));
  }

  function test_schemas_uids() public view {
    bytes32[] memory uids = resolver.getAllSchemas(IResolver.Action.ASSIGN_MANAGER);
    assert(uids.length == 1);

    bytes32[] memory uids2 = resolver.getAllSchemas(IResolver.Action.ASSIGN_VILLAGER);
    assert(uids2.length == 1);

    bytes32[] memory uids3 = resolver.getAllSchemas(IResolver.Action.ATTEST);
    assert(uids3.length == 1);

    bytes32[] memory uids4 = resolver.getAllSchemas(IResolver.Action.REPLY);
    assert(uids4.length == 1);
  }

  function test_custom_schema() public {
    bytes32 uid = schemaRegistry.register("string role,bool wtf", resolver, true);
    resolver.setSchema(uid, IResolver.Action.ATTEST);
    assert(resolver.allowedSchemas(uid) == IResolver.Action.ATTEST);

    bytes32[] memory uids = resolver.getAllSchemas(IResolver.Action.ATTEST);
    assert(uids.length == 2);
    assert(uids[1] == uid);
    assert(uids[0] == resolver.getAllSchemas(IResolver.Action.ATTEST)[0]);
  }

  function test_access_control_all_badge_titles() public {
    string[] memory registeredTitles = test_access_control_add_attest_title();
    string[] memory allTitles = resolver.getAllAttestationTitles();
    assert(allTitles.length == registeredTitles.length);
    for (uint256 i = 0; i < allTitles.length; i++) {
      assert(keccak256(abi.encode(allTitles[i])) == keccak256(abi.encode(registeredTitles[i])));
    }
    resolver.setAttestationTitle(registeredTitles[0], false);
    allTitles = resolver.getAllAttestationTitles();
    assert(allTitles.length == registeredTitles.length - 1);
    assert(keccak256(abi.encode(allTitles[0])) != keccak256(abi.encode(registeredTitles[0])));
    assert(keccak256(abi.encode(allTitles[0])) == keccak256(abi.encode(registeredTitles[1])));
    assert(keccak256(abi.encode(allTitles[1])) == keccak256(abi.encode(registeredTitles[2])));
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
