// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import { IEAS, Attestation } from "../interfaces/IEAS.sol";
import { AccessDenied, InvalidEAS, InvalidLength, uncheckedInc, EMPTY_UID } from "../Common.sol";
import { ISchemaResolver } from "../interfaces/ISchemaResolver.sol";

/// @title Resolver
/// @author Blockful
/// @notice The base schema resolver contract.
contract Resolver is ISchemaResolver {
  error InsufficientValue();
  error NotPayable();
  error Unauthorized();
  error ManagerRoleMustBeRevocable();
  error BadgeNotFound();
  error InvalidRefUID();

  // The global EAS contract.
  IEAS internal immutable _eas;

  // Roles
  bytes32 public constant ROOT_ROLE = keccak256("ROOT_ROLE");
  bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
  bytes32 public constant VILLAGER_ROLE = keccak256("VILLAGER_ROLE");

  // Allowlists
  mapping(address => bytes32) private _roles;

  // Allowed Schemas
  mapping(bytes32 => bytes32) private _schemas;

  // Allowed Badges (Attestation titles to be emitted)
  mapping(bytes32 => bool) private _badges;

  /// @dev Creates a new resolver.
  /// @param eas The address of the global EAS contract.
  constructor(IEAS eas) {
    if (address(eas) == address(0)) {
      revert InvalidEAS();
    }

    _eas = eas;

    // Assigns ROOT_ROLE to the deployer
    _roles[msg.sender] = ROOT_ROLE;
  }

  /// @dev Ensures that only the EAS contract can make this call.
  modifier onlyEAS() {
    _onlyEAS();
    _;
  }

  /// @inheritdoc ISchemaResolver
  function attest(Attestation calldata attestation) external payable onlyEAS returns (bool) {
    bytes32 role = _schemas[attestation.schema];

    // Schema to create managers
    if (role == ROOT_ROLE) {
      if (!attestation.revocable) revert ManagerRoleMustBeRevocable();
      _grantRole(attestation.recipient, MANAGER_ROLE);
      return true;
    }

    // Schema to create villagers ( checkIn / checkOut )
    if (role == MANAGER_ROLE) {
      bool isCheckedIn = abi.decode(attestation.data, (bool));
      if (!isCheckedIn) _grantRole(attestation.recipient, VILLAGER_ROLE);
      if (isCheckedIn) _revokeRole(attestation.recipient);
      return true;
    }

    // Schema to create event badges
    if (role == VILLAGER_ROLE || role == MANAGER_ROLE) {
      (string memory title, ) = abi.decode(attestation.data, (string, string));
      if (!_badges[keccak256(abi.encode(title))]) revert BadgeNotFound();
      return true;
    }

    // Schema to create a response ( true / false )
    if (role == VILLAGER_ROLE || role == MANAGER_ROLE) {
      if (attestation.refUID != EMPTY_UID) revert InvalidRefUID();
      return true;
    }

    return false;
  }

  /// @inheritdoc ISchemaResolver
  function revoke(Attestation calldata attestation) external payable onlyEAS returns (bool) {
    return false;
  }

  function _grantRole(address account, bytes32 role) internal {
    _roles[account] = role;
  }

  function _revokeRole(address account) internal {
    _roles[account] = 0x0;
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

  /// @dev Returns `true` if `account` has been granted `role`.
  function hasRole(address account, bytes32 role) public view virtual returns (bool) {
    return _roles[account] == role;
  }

  /// @dev Ensures that only the EAS contract can make this call.
  function _onlyEAS() private view {
    if (msg.sender != address(_eas)) {
      revert AccessDenied();
    }
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
