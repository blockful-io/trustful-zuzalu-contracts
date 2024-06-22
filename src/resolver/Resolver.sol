// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import { IEAS, Attestation } from "../interfaces/IEAS.sol";
import { IResolver } from "../interfaces/IResolver.sol";
import { AccessDenied, InvalidEAS, InvalidLength, uncheckedInc, EMPTY_UID, NO_EXPIRATION_TIME } from "../Common.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";

error InsufficientValue();
error NotPayable();
error Unauthorized();
error AlreadyCheckedOut();
error InvalidAttestationTitle();
error InvalidRefUID();
error InvalidExpiration();
error InvalidRevocability();

/// @title Resolver
/// @author Blockful | 0xneves
/// @notice ZuVillage Resolver contract.
contract Resolver is IResolver, AccessControl {
  // The global EAS contract.
  IEAS internal immutable _eas;

  // Roles
  bytes32 public constant ROOT_ROLE = keccak256("ROOT_ROLE");
  bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
  bytes32 public constant VILLAGER_ROLE = keccak256("VILLAGER_ROLE");

  // Addresses to booleans to check if a Villager is checked in or out
  mapping(address => bool) private _checkedOutVillagers;

  // Schemas ID to role ID to action
  mapping(bytes32 => mapping(bytes32 => Action)) private _allowedSchemas;

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

  /// @inheritdoc IResolver
  function isPayable() public pure virtual returns (bool) {
    return false;
  }

  /// @inheritdoc IResolver
  function checkedOutVillagers(address villager) public view returns (bool) {
    return _checkedOutVillagers[villager];
  }

  /// @inheritdoc IResolver
  function schemas(bytes32 uid, bytes32 roleId) public view returns (Action) {
    return _allowedSchemas[uid][roleId];
  }

  /// @inheritdoc IResolver
  function allowedAttestationTitles(string memory title) public view returns (bool) {
    return _allowedAttestationTitles[keccak256(abi.encode(title))];
  }

  /// @inheritdoc IResolver
  function attest(Attestation calldata attestation) external payable onlyEAS returns (bool) {
    // Prohibits the attestation expiration to be finite
    if (attestation.expirationTime != NO_EXPIRATION_TIME) revert InvalidExpiration();

    // Schema to assign managers
    if (_allowedSchemas[attestation.schema][ROOT_ROLE] == Action.ASSIGN_MANAGER) {
      if (!attestation.revocable) revert InvalidRevocability();
      _checkRole(ROOT_ROLE, attestation.attester);
      _grantRole(MANAGER_ROLE, attestation.recipient);
      return true;
    }

    // Schema to assign villagers ( checkIn / checkOut )
    if (_allowedSchemas[attestation.schema][MANAGER_ROLE] == Action.ASSIGN_VILLAGER) {
      if (attestation.revocable) revert InvalidRevocability();
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
    if (_allowedSchemas[attestation.schema][VILLAGER_ROLE] == Action.ATTEST) {
      if (!attestation.revocable) revert InvalidRevocability();
      _checkRole(VILLAGER_ROLE, attestation.attester);

      // Titles for attestations must be included by the managers
      (string memory title, ) = abi.decode(attestation.data, (string, string));
      if (!_allowedAttestationTitles[keccak256(abi.encode(title))]) revert InvalidAttestationTitle();

      return true;
    }

    // Schema to create a response ( true / false )
    if (_allowedSchemas[attestation.schema][VILLAGER_ROLE] == Action.REPLY) {
      if (!attestation.revocable) revert InvalidRevocability();
      _checkRole(VILLAGER_ROLE, attestation.attester);

      // Checks if the attestation has a non empty reference
      if (attestation.refUID != EMPTY_UID) revert InvalidRefUID();
      Attestation memory attesterRef = _eas.getAttestation(attestation.refUID);
      // Match the attester of this attestation with the recipient of the reference attestation
      // The response is designed to be a reply to a previous attestation
      if (attesterRef.recipient != attestation.attester) revert InvalidRefUID();

      return true;
    }
    return false;
  }

  /// @inheritdoc IResolver
  function revoke(Attestation calldata attestation) external payable onlyEAS returns (bool) {
    // Schema to revoke managers
    if (_allowedSchemas[attestation.schema][ROOT_ROLE] == Action.ASSIGN_MANAGER) {
      _checkRole(ROOT_ROLE, attestation.attester);
      _checkRole(MANAGER_ROLE, attestation.recipient);
      _revokeRole(MANAGER_ROLE, attestation.recipient);
      return true;
    }

    return false;
  }

  /// @inheritdoc IResolver
  function setSchema(bytes32 uid, bytes32 roleId, uint256 action) public onlyRole(ROOT_ROLE) {
    _allowedSchemas[uid][roleId] = Action(action);
  }

  /// @inheritdoc IResolver
  function setAttestationTitle(string memory title, bool isValid) public onlyRole(ROOT_ROLE) {
    _allowedAttestationTitles[keccak256(abi.encode(title))] = isValid;
  }

  /// @dev ETH callback.
  receive() external payable virtual {
    if (!isPayable()) {
      revert NotPayable();
    }
  }
}
