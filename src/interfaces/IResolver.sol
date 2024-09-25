// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import { Attestation } from "../Common.sol";

/// @notice The interface of the {Resolver} contract.
interface IResolver {
  /// @notice Actions that can be performed by the resolver.
  enum Action {
    NONE,
    ASSIGN_MANAGER,
    ASSIGN_VILLAGER,
    ATTEST,
    REPLY
  }

  /// @notice Checks if the resolver can be sent ETH.
  /// @return Whether the resolver supports ETH transfers.
  function isPayable() external pure returns (bool);

  /// @dev Checks if a title is allowed to be attested.
  function allowedAttestationTitles(string memory title) external view returns (bool);

  /// @dev Validates if an attestation can have a response.
  function cannotReply(bytes32 uid) external view returns (bool);

  /// @dev Checks which action a role can perform on a schema.
  function allowedSchemas(bytes32 uid) external view returns (Action);

  /// @notice Processes an attestation and verifies whether it's valid.
  /// @param attestation The new attestation.
  /// @return Whether the attestation is valid.
  function attest(Attestation calldata attestation) external payable returns (bool);

  /// @notice Processes an attestation revocation and verifies if it can be revoked.
  /// @param attestation The existing attestation to be revoked.
  /// @return Whether the attestation can be revoked.
  function revoke(Attestation calldata attestation) external payable returns (bool);

  /// @notice This function will retrieve all titles allowed in the resolver.
  /// It was designed to aid the frontend in displaying the current badges available.
  /// NOTE: Only the badges marked as valid will be returned.
  /// @return An array of all attestation titles.
  function getAllAttestationTitles() external view returns (string[] memory);

  /// @dev Sets the attestation for a given title that will be attested.
  /// When creating attestions, the title must match to the desired configuration saved
  /// on the resolver.
  /// @param title The title of the attestation.
  /// @param isValid Whether the title for the attestation is valid or not. Defaults to false.
  function setAttestationTitle(string memory title, bool isValid) external;

  /// @dev Sets the action ID that schema can perform.
  /// The schema determines the data layout for the attestation, while the attestation
  /// determines the data that will fill the schema data.
  /// @param uid The UID of the schema.
  /// @param action The action that the role can perform on the schema.
  function setSchema(bytes32 uid, uint256 action) external;
}
