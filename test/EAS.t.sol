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
  address villager2 = 0x0e949072efd935bfba099786af9d32B00AAF000F;

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
    bytes32 assignedManagerUID = attest_manager(uids[0], manager, "Manager");

    // Check-In Villagers
    vm.startPrank(manager);
    bytes32 attestVillagerUID = attest_villager_checkin(uids[1], villager, "Check-in");
    attest_villager_checkin(uids[1], manager, "Check-in"); // assigns himself as a villager as well (checkIn)
    assert(IAccessControl(address(resolver)).hasRole(VILLAGER_ROLE, villager));
    assert(IAccessControl(address(resolver)).hasRole(VILLAGER_ROLE, manager));

    // Attest Event
    vm.startPrank(villager);
    bytes32 eventUID = attest_event(uids[2], manager, titles[0], "This address changed my mind");

    // Attest Response
    vm.startPrank(manager);
    bytes32 responseUID = attest_response(uids[3], villager, eventUID, true);
    assert(resolver.cannotReply(eventUID));
    // Should fail to attest response again
    assert(!try_attest_response(uids[3], villager, eventUID, true));
    // Should be able to revoke the response
    attest_response_revoke(uids[3], responseUID);
    assert(!resolver.cannotReply(eventUID));
    // Should be able to re-attest response
    attest_response(uids[3], villager, eventUID, false);
    assert(resolver.cannotReply(eventUID));

    // Check-Out Villager as Himself
    vm.startPrank(villager);
    attest_villager_checkout(uids[1], villager, "Check-out", attestVillagerUID);
    assert(!IAccessControl(address(resolver)).hasRole(VILLAGER_ROLE, villager));
    // Should fail to check-out again
    assert(!try_attest_villager_checkout(uids[1], villager, "Check-out", attestVillagerUID));

    // Check-Out Villager as Manager
    vm.startPrank(manager);
    bytes32 attestVillager2UID = attest_villager_checkin(uids[1], villager2, "Check-in");
    attest_villager_checkout(uids[1], villager2, "Check-out", attestVillager2UID);
    assert(!IAccessControl(address(resolver)).hasRole(VILLAGER_ROLE, villager2));
    // Should fail to check-out again
    assert(!try_attest_villager_checkout(uids[1], villager2, "Check-out", attestVillager2UID));

    // Villager cannot receive event badges after checkout
    vm.startPrank(manager);
    assert(!try_attest_event(uids[2], villager2, titles[1], "This address is a good person"));

    // Villager can be checked-in again
    vm.startPrank(manager);
    bytes32 attestVillagerUIDSecondTime = attest_villager_checkin(uids[1], villager, "Check-in");
    // Should have the VILLAGER_ROLE
    assert(IAccessControl(address(resolver)).hasRole(VILLAGER_ROLE, villager));
    // Should be able to attest events again
    vm.startPrank(villager);
    attest_event(uids[2], manager, titles[2], "This address has a brilliant mind");
    // Should be able to check-out once more
    attest_villager_checkout(uids[1], villager, "Check-out", attestVillagerUIDSecondTime);

    // Revoke Manager
    vm.startPrank(deployer);
    attest_manager_revoke(uids[0], assignedManagerUID);
    assert(!IAccessControl(address(resolver)).hasRole(MANAGER_ROLE, manager));

    // Fail to Revoke Manager a second time
    assert(!try_attest_manager_revoke(uids[0], assignedManagerUID));
  }

  function register_allowed_schemas() public returns (bytes32[] memory) {
    bytes32[] memory uids = new bytes32[](4);

    /// ASSIGN MANAGER SCHEMA - Action(1)
    string memory schema = "string role";
    bool revocable = true;
    uids[0] = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uids[0], 1);

    /// ASSIGN VILLAGER SCHEMA - Action(2)
    schema = "string status";
    revocable = false;
    uids[1] = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uids[1], 2);

    /// Event Attestation SCHEMA - Action(3)
    schema = "string title,string comment";
    revocable = false;
    uids[2] = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uids[2], 3);

    /// Event Response SCHEMA - Action(4)
    schema = "bool status";
    revocable = true;
    uids[3] = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uids[3], 4);

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

  function attest_manager(
    bytes32 schemaUID,
    address recipient,
    string memory role
  ) public returns (bytes32) {
    return
      eas.attest(
        AttestationRequest({
          schema: schemaUID,
          data: AttestationRequestData({
            recipient: recipient,
            expirationTime: 0,
            revocable: true,
            refUID: 0,
            data: abi.encode(role),
            value: 0
          })
        })
      );
  }

  function attest_villager_checkin(
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

  function attest_villager_checkout(
    bytes32 schemaUID,
    address recipient,
    string memory status,
    bytes32 refUID
  ) public returns (bytes32) {
    return
      eas.attest(
        AttestationRequest({
          schema: schemaUID,
          data: AttestationRequestData({
            recipient: recipient,
            expirationTime: 0,
            revocable: false,
            refUID: refUID,
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

  function try_attest_villager_checkout(
    bytes32 schemaUID,
    address recipient,
    string memory status,
    bytes32 refUID
  ) public returns (bool) {
    try
      eas.attest(
        AttestationRequest({
          schema: schemaUID,
          data: AttestationRequestData({
            recipient: recipient,
            expirationTime: 0,
            revocable: false,
            refUID: refUID,
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

  function try_attest_event(
    bytes32 schemaUID,
    address recipient,
    string memory title,
    string memory comment
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
            data: abi.encode(title, comment),
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

  function try_attest_response(
    bytes32 schemaUID,
    address recipient,
    bytes32 refUID,
    bool status
  ) public returns (bool) {
    try
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

  function try_attest_manager_revoke(
    bytes32 schemaUID,
    bytes32 attestationUID
  ) public returns (bool) {
    try
      eas.revoke(
        RevocationRequest({
          schema: schemaUID,
          data: RevocationRequestData({ uid: attestationUID, value: 0 })
        })
      )
    {
      return true;
    } catch {
      return false;
    }
  }
}
