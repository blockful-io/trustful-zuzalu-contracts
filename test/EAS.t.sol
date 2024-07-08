// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Test, console2 } from "forge-std/src/Test.sol";
import { Resolver } from "../src/resolver/Resolver.sol";
import { IResolver } from "../src/interfaces/IResolver.sol";
import { ISchemaRegistry } from "../src/interfaces/ISchemaRegistry.sol";
import { IEAS, AttestationRequest, AttestationRequestData, RevocationRequest, RevocationRequestData } from "../src/interfaces/IEAS.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";

contract ResolverTest is Test {
  IEAS eas = IEAS(0x4200000000000000000000000000000000000021);
  ISchemaRegistry schemaRegistry = ISchemaRegistry(0x4200000000000000000000000000000000000020);
  IResolver resolver;

  bytes32 ROOT_ROLE = keccak256("ROOT_ROLE");
  bytes32 MANAGER_ROLE = keccak256("MANAGER_ROLE");
  bytes32 VILLAGER_ROLE = keccak256("VILLAGER_ROLE");

  address deployer = 0xF977814e90dA44bFA03b6295A0616a897441aceC;
  address manager = 0x96DB2c6D93A8a12089f7a6EdA5464e967308AdEd;
  address villager = 0xe700CCEB04d34b798B5f8b7c35E91231445Ff6C0;

  function setUp() public {
    vm.label(deployer, "ROOT");
    vm.label(manager, "MANAGER");
    vm.label(villager, "VILLAGER");
    vm.startPrank(deployer);
    resolver = new Resolver(eas);
  }

  function test_attestations() public {
    bytes32[] memory uids = register_allowed_schemas();
    string[] memory titles = register_allowed_titles();

    // Assign manager
    bytes32 assignedManagerUID = attest_manager(uids[0], manager);

    // Check-In Villagers
    vm.startPrank(manager);
    attest_villager(uids[1], villager, "Check-in");
    attest_villager(uids[1], manager, "Check-in"); // assigns himself as a villager as well (checkIn)
    assert(IAccessControl(address(resolver)).hasRole(VILLAGER_ROLE, villager));
    assert(IAccessControl(address(resolver)).hasRole(VILLAGER_ROLE, manager));

    // Attest Event
    vm.startPrank(villager);
    bytes32 eventUID = attest_event(uids[2], manager, titles[0], "This address changed my mind");

    // Attest Responses, then revoke it
    vm.startPrank(manager);
    bytes32 responseUID = attest_response(uids[3], villager, eventUID, true);
    attest_response_revoke(uids[3], responseUID);

    // Check-Out Villagers
    vm.startPrank(villager);
    attest_villager(uids[1], villager, "Check-out");
    assert(!IAccessControl(address(resolver)).hasRole(VILLAGER_ROLE, villager));
    assert(resolver.checkedOutVillagers(villager));
    // Should fail to check-out again
    assert(!try_attest_villager(uids[1], villager, "Check-out"));
    // Should fail to check-in again
    assert(!try_attest_villager(uids[1], villager, "Check-in"));

    // Revoke Manager
    vm.startPrank(deployer);
    attest_manager_revoke(uids[0], assignedManagerUID);
    assert(!IAccessControl(address(resolver)).hasRole(MANAGER_ROLE, manager));
  }

  function register_allowed_schemas() public returns (bytes32[] memory) {
    bytes32[] memory uids = new bytes32[](4);

    /// ASSIGN MANAGER SCHEMA - Action(1)
    string memory schema = "string role";
    bool revocable = true;
    uids[0] = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uids[0], ROOT_ROLE, 1);

    /// ASSIGN VILLAGER SCHEMA - Action(2)
    schema = "string status";
    revocable = false;
    uids[1] = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uids[1], MANAGER_ROLE, 2);

    /// Event Attestation SCHEMA - Action(3)
    schema = "string title,string comment";
    revocable = false;
    uids[2] = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uids[2], VILLAGER_ROLE, 3);

    /// Event Response SCHEMA - Action(4)
    schema = "bool status";
    revocable = true;
    uids[3] = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uids[3], VILLAGER_ROLE, 4);

    return uids;
  }

  function register_allowed_titles() public returns (string[] memory) {
    string[] memory titles = new string[](3);
    titles[0] = "Changed My Mind";
    titles[1] = "Is a good person";
    titles[2] = "Has a brilliant mind";

    resolver.setAttestationTitle(titles[0], true);
    resolver.setAttestationTitle(titles[1], true);
    resolver.setAttestationTitle(titles[2], true);

    return titles;
  }

  function attest_manager(bytes32 schemaUID, address recipient) public returns (bytes32) {
    return
      eas.attest(
        AttestationRequest({
          schema: schemaUID,
          data: AttestationRequestData({
            recipient: recipient,
            expirationTime: 0,
            revocable: true,
            refUID: 0,
            data: "",
            value: 0
          })
        })
      );
  }

  function attest_villager(
    bytes32 schemaUID,
    address recipient,
    string memory status
  ) public returns (bytes32) {
    return
      eas.attest(
        AttestationRequest({
          schema: schemaUID,
          data: AttestationRequestData({
            recipient: recipient,
            expirationTime: 0,
            revocable: false,
            refUID: 0,
            data: abi.encode(status),
            value: 0
          })
        })
      );
  }

  function attest_event(
    bytes32 schemaUID,
    address recipient,
    string memory title,
    string memory comment
  ) public returns (bytes32) {
    return
      eas.attest(
        AttestationRequest({
          schema: schemaUID,
          data: AttestationRequestData({
            recipient: recipient,
            expirationTime: 0,
            revocable: false,
            refUID: 0,
            data: abi.encode(title, comment),
            value: 0
          })
        })
      );
  }

  function attest_response(
    bytes32 schemaUID,
    address recipient,
    bytes32 refUID,
    bool status
  ) public returns (bytes32) {
    return
      eas.attest(
        AttestationRequest({
          schema: schemaUID,
          data: AttestationRequestData({
            recipient: recipient,
            expirationTime: 0,
            revocable: true,
            refUID: refUID,
            data: abi.encode(status),
            value: 0
          })
        })
      );
  }

  function try_attest_villager(
    bytes32 schemaUID,
    address recipient,
    string memory status
  ) public returns (bool) {
    try
      eas.attest(
        AttestationRequest({
          schema: schemaUID,
          data: AttestationRequestData({
            recipient: recipient,
            expirationTime: 0,
            revocable: false,
            refUID: 0,
            data: abi.encode(status),
            value: 0
          })
        })
      )
    {
      return true;
    } catch {
      return false;
    }
  }

  function attest_response_revoke(bytes32 schemaUID, bytes32 attestationUID) public {
    eas.revoke(
      RevocationRequest({
        schema: schemaUID,
        data: RevocationRequestData({ uid: attestationUID, value: 0 })
      })
    );
  }

  function attest_manager_revoke(bytes32 schemaUID, bytes32 attestationUID) public {
    eas.revoke(
      RevocationRequest({
        schema: schemaUID,
        data: RevocationRequestData({ uid: attestationUID, value: 0 })
      })
    );
  }
}
