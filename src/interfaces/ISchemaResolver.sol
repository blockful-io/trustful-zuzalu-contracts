// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import { Attestation } from "../Common.sol";

/// @title ISchemaResolver
/// @notice The interface of an optional schema resolver.
interface ISchemaResolver {
  /// @notice Actions that can be performed by the resolver.
  enum Action {
    ASSIGN_MANAGER,
    ASSIGN_VILLAGER,
    ATTEST,
    REPLY
  }

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
}
