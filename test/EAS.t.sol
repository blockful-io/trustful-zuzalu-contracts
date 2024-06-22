// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Test, console2 } from "forge-std/src/Test.sol";
import { Resolver } from "../src/resolver/Resolver.sol";
import { IResolver } from "../src/interfaces/IResolver.sol";
import { ISchemaRegistry } from "../src/interfaces/ISchemaRegistry.sol";
import { IEAS, AttestationRequest, AttestationRequestData } from "../src/interfaces/IEAS.sol";
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

    attest_manager(uids[0], manager);

    vm.startPrank(manager);
    attest_villager(uids[1], villager);
    attest_villager(uids[1], manager); // assigns himself as a villager as well (checkIn)

    vm.startPrank(villager);
    bytes32 uid = attest_event(uids[2], manager, titles[0], "This address changed my mind");

    vm.startPrank(manager);
    attest_response(uids[3], villager, uid, true);
  }

  function register_allowed_schemas() public returns (bytes32[] memory) {
    bytes32[] memory uids = new bytes32[](4);

    /// ASSIGN MANAGER SCHEMA
    string memory schema = "";
    bool revocable = true;
    uids[0] = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uids[0], ROOT_ROLE, 1);

    /// ASSIGN VILLAGER SCHEMA
    schema = "";
    revocable = false;
    uids[1] = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uids[1], MANAGER_ROLE, 2);

    /// Event Attestation SCHEMA
    schema = "string title, string comment";
    revocable = false;
    uids[2] = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uids[2], VILLAGER_ROLE, 3);

    /// Event Response SCHEMA
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

  function attest_manager(bytes32 uid, address recipient) public returns (bytes32) {
    return
      eas.attest(
        AttestationRequest({
          schema: uid,
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

  function attest_villager(bytes32 uid, address recipient) public returns (bytes32) {
    return
      eas.attest(
        AttestationRequest({
          schema: uid,
          data: AttestationRequestData({
            recipient: recipient,
            expirationTime: 0,
            revocable: false,
            refUID: 0,
            data: "",
            value: 0
          })
        })
      );
  }

  function attest_event(
    bytes32 uid,
    address recipient,
    string memory title,
    string memory comment
  ) public returns (bytes32) {
    return
      eas.attest(
        AttestationRequest({
          schema: uid,
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

  function attest_response(bytes32 uid, address recipient, bytes32 refUID, bool status) public returns (bytes32) {
    return
      eas.attest(
        AttestationRequest({
          schema: uid,
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
}
