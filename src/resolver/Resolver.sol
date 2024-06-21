// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import { IEAS, Attestation } from "../interfaces/IEAS.sol";
import { ISchemaResolver } from "../interfaces/ISchemaResolver.sol";
import { AccessDenied, InvalidEAS, InvalidLength, uncheckedInc, EMPTY_UID } from "../Common.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";

error InsufficientValue();
error NotPayable();
error Unauthorized();
error ManagerRoleMustBeRevocable();
error BadgeNotFound();
error InvalidRefUID();

/// @title Resolver
/// @author Blockful
/// @notice The base schema resolver contract.
contract Resolver is ISchemaResolver, AccessControl {
  // The global EAS contract.
  IEAS internal immutable _eas;

  // Roles
  bytes32 public constant ROOT_ROLE = keccak256("ROOT_ROLE");
  bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
  bytes32 public constant VILLAGER_ROLE = keccak256("VILLAGER_ROLE");

  // Schemas to Role ID
  mapping(bytes32 => bytes32) private _schemas;

  // Allowed Badges (Hashed titles that can be attested)
  mapping(bytes32 => bool) private _badges;

  /// @dev Creates a new resolver.
  /// @param eas The address of the global EAS contract.
  constructor(IEAS eas) {
    if (address(eas) == address(0)) revert InvalidEAS();
    _eas = eas;

    // Assigns ROOT_ROLE to the deployer
    _grantRole(ROOT_ROLE, msg.sender);
    // Assigns ROOT_ROLE as the admin of all roles
    _setRoleAdmin(ROOT_ROLE, ROOT_ROLE);
    _setRoleAdmin(MANAGER_ROLE, ROOT_ROLE);
    _setRoleAdmin(VILLAGER_ROLE, ROOT_ROLE);
  }

  /// @dev Ensures that only the EAS contract can make this call.
  modifier onlyEAS() {
    if (msg.sender != address(_eas)) revert AccessDenied();
    _;
  }

  /// @inheritdoc ISchemaResolver
  function attest(Attestation calldata attestation) external payable onlyEAS returns (bool) {
    bytes32 roleId = _schemas[attestation.schema];

    // Schema to create managers
    if (roleId == ROOT_ROLE) {
      if (!attestation.revocable) revert ManagerRoleMustBeRevocable();
      _grantRole(MANAGER_ROLE, attestation.recipient);
      return true;
    }

    // Schema to create villagers ( checkIn / checkOut )
    if (roleId == MANAGER_ROLE) {
      bool isCheckedIn = abi.decode(attestation.data, (bool));
      if (!isCheckedIn) _grantRole(VILLAGER_ROLE, attestation.recipient);
      if (isCheckedIn) _revokeRole(VILLAGER_ROLE, attestation.recipient);
      return true;
    }

    // Schema to create event badges
    if (roleId == VILLAGER_ROLE || roleId == MANAGER_ROLE) {
      (string memory title, ) = abi.decode(attestation.data, (string, string));
      if (!_badges[keccak256(abi.encode(title))]) revert BadgeNotFound();
      return true;
    }

    // Schema to create a response ( true / false )
    if (roleId == VILLAGER_ROLE || roleId == MANAGER_ROLE) {
      if (attestation.refUID != EMPTY_UID) revert InvalidRefUID();
      return true;
    }

    return false;
  }

  /// @inheritdoc ISchemaResolver
  function revoke(Attestation calldata attestation) external payable onlyEAS returns (bool) {
    bytes32 role = _schemas[attestation.schema];

    // Schema to revoke managers
    if (role == ROOT_ROLE) {
      _revokeRole(MANAGER_ROLE, attestation.recipient);
      return true;
    }

    return false;
  }

  function addSchema(bytes32 uid, bytes32 role) public {
    _schemas[uid] = role;
  }

  function revokeSchema(bytes32 uid) public {
    _schemas[uid] = 0x0;
  }

  function addBadge(string memory title) public {
    _badges[keccak256(abi.encode(title))] = true;
  }

  function revokeBadge(string memory title) public {
    _badges[keccak256(abi.encode(title))] = false;
  }

  /// @inheritdoc ISchemaResolver
  function isPayable() public pure virtual returns (bool) {
    return false;
  }

  /// @dev ETH callback.
  receive() external payable virtual {
    if (!isPayable()) {
      revert NotPayable();
    }
  }
}
