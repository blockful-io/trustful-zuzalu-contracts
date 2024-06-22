// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import { Attestation } from "../Common.sol";

/// @title IResolver
/// @notice The interface of an optional schema resolver.
interface IResolver {
  /// @notice Actions that can be performed by the resolver.
  enum Action {
    NONE,
    ASSIGN_MANAGER,
    ASSIGN_VILLAGER,
    ATTEST,
    REPLY
  }

  /// @dev Checks if a villager is checkedOut.
  function checkedOutVillagers(address villager) external view returns (bool);

  /// @dev Checks which action a role can perform on a schema.
  function schemas(bytes32 uid, bytes32 roleId) external view returns (Action);

  /// @dev Checks if a title is allowed to be attested.
  function allowedAttestationTitles(string memory title) external view returns (bool);

  /// @notice Checks if the resolver can be sent ETH.
  /// @return Whether the resolver supports ETH transfers.
  function isPayable() external pure returns (bool);

  /// @notice Processes an attestation and verifies whether it's valid.
  /// @param attestation The new attestation.
  /// @return Whether the attestation is valid.
  function attest(Attestation calldata attestation) external payable returns (bool);

  /// @notice Processes an attestation revocation and verifies if it can be revoked.
  /// @param attestation The existing attestation to be revoked.
  /// @return Whether the attestation can be revoked.
  function revoke(Attestation calldata attestation) external payable returns (bool);

  /// @dev Sets the role ID that can attest using a schema.
  /// The schema determines the data layout for the attestation, while the attestation
  /// determines the data that will fill the schema. When hooking the resolver from the
  /// EAS contract, the attester should hodl the right role to attest with the schema.
  /// @param uid The UID of the schema.
  /// @param roleId The role ID that are allowed to attest using the schema.
  function setSchema(bytes32 uid, bytes32 roleId, uint256 action) external;

  /// @dev Sets the attestation for a given title that will be attested.
  /// When creating attestions, the title must match to the desired configuration saved
  /// on the resolver.
  /// @param title The title of the attestation.
  /// @param isValid Whether the title for the attestation is valid or not. Defaults to false.
  function setAttestationTitle(string memory title, bool isValid) external;
}
