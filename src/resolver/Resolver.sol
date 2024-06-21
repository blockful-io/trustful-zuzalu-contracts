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
error AttestationTitleNotFound();
error InvalidRefUID();
error AlreadyCheckedOut();

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

  // Addresses to booleans to check if a Villager is checked in or out
  mapping(address => bool) private _checkedOutVillagers;

  // Schemas ID to role ID to action
  mapping(bytes32 => mapping(bytes32 => Action)) private _schemas;

  // Allowed Attestations (Hashed titles that can be attested)
  mapping(bytes32 => bool) private _allowedAttestationTitles;

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
  function isPayable() public pure virtual returns (bool) {
    return false;
  }

  /// @inheritdoc ISchemaResolver
  function attest(Attestation calldata attestation) external payable onlyEAS returns (bool) {
    // Schema to assign managers
    if (_schemas[attestation.schema][ROOT_ROLE] == Action.ASSIGN_MANAGER) {
      if (!attestation.revocable) revert ManagerRoleMustBeRevocable();

      _checkRole(ROOT_ROLE, attestation.attester);
      _grantRole(MANAGER_ROLE, attestation.recipient);

      return true;
    }

    // Schema to assign villagers ( checkIn / checkOut )
    if (_schemas[attestation.schema][MANAGER_ROLE] == Action.ASSIGN_VILLAGER) {
      _checkRole(MANAGER_ROLE, attestation.attester);

      // Check in if doesn't have Villager Role and is not checked out
      if (!hasRole(VILLAGER_ROLE, attestation.recipient) && !_checkedOutVillagers[attestation.recipient]) {
        _grantRole(VILLAGER_ROLE, attestation.recipient);
        // Check out if has Villager Role and is not checked out
      } else if (hasRole(VILLAGER_ROLE, attestation.recipient) && !_checkedOutVillagers[attestation.recipient]) {
        _revokeRole(VILLAGER_ROLE, attestation.recipient);
        _checkedOutVillagers[attestation.recipient] = true;
      } else {
        revert AlreadyCheckedOut();
      }

      return true;
    }

    // Schema to create event attestations (Attestations)
    if (
      _schemas[attestation.schema][VILLAGER_ROLE] == Action.ATTEST ||
      _schemas[attestation.schema][MANAGER_ROLE] == Action.ATTEST
    ) {
      if (!hasRole(VILLAGER_ROLE, attestation.attester) && !hasRole(MANAGER_ROLE, attestation.attester)) {
        revert AccessControlBadConfirmation();
      }

      (string memory title, ) = abi.decode(attestation.data, (string, string));
      if (!_allowedAttestationTitles[keccak256(abi.encode(title))]) revert AttestationTitleNotFound();

      return true;
    }

    // Schema to create a response ( true / false )
    if (
      _schemas[attestation.schema][VILLAGER_ROLE] == Action.REPLY ||
      _schemas[attestation.schema][MANAGER_ROLE] == Action.REPLY
    ) {
      if (!hasRole(VILLAGER_ROLE, attestation.attester) && !hasRole(MANAGER_ROLE, attestation.attester)) {
        revert AccessControlBadConfirmation();
      }

      if (attestation.refUID != EMPTY_UID) revert InvalidRefUID();
      Attestation memory attesterRef = _eas.getAttestation(attestation.refUID);
      if (attesterRef.recipient != attestation.attester) revert InvalidRefUID();

      return true;
    }
    return false;
  }

  /// @inheritdoc ISchemaResolver
  function revoke(Attestation calldata attestation) external payable onlyEAS returns (bool) {
    // Schema to revoke managers
    if (_schemas[attestation.schema][ROOT_ROLE] == Action.ASSIGN_MANAGER) {
      _checkRole(ROOT_ROLE, attestation.attester);
      _checkRole(MANAGER_ROLE, attestation.recipient);
      _revokeRole(MANAGER_ROLE, attestation.recipient);
      return true;
    }

    return false;
  }

  /// @dev Sets the role ID that can attest using a schema.
  /// The schema determines the data layout for the attestation, while the attestation
  /// determines the data that will fill the schema. When hooking the resolver from the
  /// EAS contract, the attester should hodl the right role to attest with the schema.
  /// @param uid The UID of the schema.
  /// @param roleId The role ID that are allowed to attest using the schema.
  function setSchema(bytes32 uid, bytes32 roleId, uint256 action) public {
    _schemas[uid][roleId] = Action(action);
  }

  /// @dev Sets the attestation for a given title that will be attested.
  /// When creating attestions, the title must match to the desired configuration saved
  /// on the resolver.
  /// @param title The title of the attestation.
  /// @param isValid Whether the title for the attestation is valid or not. Defaults to false.
  function setAttestationTitle(string memory title, bool isValid) public {
    _allowedAttestationTitles[keccak256(abi.encode(title))] = isValid;
  }

  /// @dev ETH callback.
  receive() external payable virtual {
    if (!isPayable()) {
      revert NotPayable();
    }
  }
}
