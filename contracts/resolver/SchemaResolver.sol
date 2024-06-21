// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import { IEAS, Attestation } from "../IEAS.sol";
import { AccessDenied, InvalidEAS, InvalidLength, uncheckedInc } from "../Common.sol";
import { Semver } from "../Semver.sol";
import { ISchemaResolver } from "./ISchemaResolver.sol";

/// @title SchemaResolver
/// @notice The base schema resolver contract.
abstract contract SchemaResolver is ISchemaResolver, Semver {
    error InsufficientValue();
    error NotPayable();
    error Unauthorized();

    // The global EAS contract.
    IEAS internal immutable _eas;

    // Roles
    bytes32 public constant ROOT_ROLE = keccak256("ROOT_ROLE");
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant VILLAGER_ROLE = keccak256("VILLAGER_ROLE");

    // Allowlist mapping
    mapping(address => bytes32) public roles;

    /// @dev Creates a new resolver.
    /// @param eas The address of the global EAS contract.
    constructor(IEAS eas) Semver(1, 3, 0) {
        if (address(eas) == address(0)) {
            revert InvalidEAS();
        }

        _eas = eas;

        // Assign ROOT_ROLE to the deployer
        roles[msg.sender] = ROOT_ROLE;
    }

    /// @dev Ensures that only the EAS contract can make this call.
    modifier onlyEAS() {
        _onlyEAS();
        _;
    }

    /// @dev Ensures that the caller has the specified role.
    modifier onlyRole(bytes32 role) {
        if (roles[msg.sender] != role) {
            revert Unauthorized();
        }
        _;
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

    /// @inheritdoc ISchemaResolver
    function attest(Attestation calldata attestation) external payable onlyEAS returns (bool) {
        // Verify permissions
        if (roles[attestation.attester] == MANAGER_ROLE && roles[attestation.recipient] == VILLAGER_ROLE) {
            return onAttest(attestation, msg.value);
        } else if (roles[attestation.attester] == ROOT_ROLE && roles[attestation.recipient] == MANAGER_ROLE) {
            return onAttest(attestation, msg.value);
        } else if (roles[attestation.attester] == ROOT_ROLE) {
            return onAttest(attestation, msg.value);
        } else {
            revert Unauthorized();
        }
    }

    /// @inheritdoc ISchemaResolver
    function multiAttest(
        Attestation[] calldata attestations,
        uint256[] calldata values
    ) external payable onlyEAS returns (bool) {
        uint256 length = attestations.length;
        if (length != values.length) {
            revert InvalidLength();
        }

        uint256 remainingValue = msg.value;

        for (uint256 i = 0; i < length; i = uncheckedInc(i)) {
            uint256 value = values[i];
            if (value > remainingValue) {
                revert InsufficientValue();
            }

            if (!attest(attestations[i])) {
                return false;
            }

            unchecked {
                remainingValue -= value;
            }
        }

        return true;
    }

    /// @inheritdoc ISchemaResolver
    function revoke(Attestation calldata attestation) external payable onlyEAS returns (bool) {
        return onRevoke(attestation, msg.value);
    }

    /// @inheritdoc ISchemaResolver
    function multiRevoke(
        Attestation[] calldata attestations,
        uint256[] calldata values
    ) external payable onlyEAS returns (bool) {
        uint256 length = attestations.length;
        if (length != values.length) {
            revert InvalidLength();
        }

        uint256 remainingValue = msg.value;

        for (uint256 i = 0; i < length; i = uncheckedInc(i)) {
            uint256 value = values[i];
            if (value > remainingValue) {
                revert InsufficientValue();
            }

            if (!revoke(attestations[i])) {
                return false;
            }

            unchecked {
                remainingValue -= value;
            }
        }

        return true;
    }

    /// @notice A resolver callback that should be implemented by child contracts.
    /// @param attestation The new attestation.
    /// @param value An explicit ETH amount that was sent to the resolver.
    /// @return Whether the attestation is valid.
    function onAttest(Attestation calldata attestation, uint256 value) internal virtual returns (bool);

    /// @notice Processes an attestation revocation and verifies if it can be revoked.
    /// @param attestation The existing attestation to be revoked.
    /// @param value An explicit ETH amount that was sent to the resolver.
    /// @return Whether the attestation can be revoked.
    function onRevoke(Attestation calldata attestation, uint256 value) internal virtual returns (bool);

    /// @dev Ensures that only the EAS contract can make this call.
    function _onlyEAS() private view {
        if (msg.sender != address(_eas)) {
            revert AccessDenied();
        }
    }

    /// @notice Assigns a role to an address.
    /// @param account The address to assign the role to.
    /// @param role The role to assign.
    function assignRole(address account, bytes32 role) external onlyRole(ROOT_ROLE) {
        roles[account] = role;
    }
}