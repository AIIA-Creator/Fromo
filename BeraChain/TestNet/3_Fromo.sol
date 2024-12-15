// Sources flattened with hardhat v2.22.3 https://hardhat.org

// SPDX-License-Identifier: MIT

pragma experimental ABIEncoderV2;

// File @openzeppelin/contracts/access/IAccessControl.sol@v5.0.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (access/IAccessControl.sol)

pragma solidity ^0.8.20;

/**
 * @dev External interface of AccessControl declared to support ERC165 detection.
 */
interface IAccessControl {
    /**
     * @dev The `account` is missing a role.
     */
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

    /**
     * @dev The caller of a function is not the expected one.
     *
     * NOTE: Don't confuse with {AccessControlUnauthorizedAccount}.
     */
    error AccessControlBadConfirmation();

    /**
     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     *
     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
     * {RoleAdminChanged} not being emitted signaling this.
     */
    event RoleAdminChanged(
        bytes32 indexed role,
        bytes32 indexed previousAdminRole,
        bytes32 indexed newAdminRole
    );

    /**
     * @dev Emitted when `account` is granted `role`.
     *
     * `sender` is the account that originated the contract call, an admin role
     * bearer except when using {AccessControl-_setupRole}.
     */
    event RoleGranted(
        bytes32 indexed role,
        address indexed account,
        address indexed sender
    );

    /**
     * @dev Emitted when `account` is revoked `role`.
     *
     * `sender` is the account that originated the contract call:
     *   - if using `revokeRole`, it is the admin role bearer
     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
     */
    event RoleRevoked(
        bytes32 indexed role,
        address indexed account,
        address indexed sender
    );

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(
        bytes32 role,
        address account
    ) external view returns (bool);

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {AccessControl-_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) external view returns (bytes32);

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function revokeRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     */
    function renounceRole(bytes32 role, address callerConfirmation) external;
}

// File @openzeppelin/contracts/utils/Context.sol@v5.0.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

pragma solidity ^0.8.20;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}

// File @openzeppelin/contracts/utils/introspection/IERC165.sol@v5.0.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/introspection/IERC165.sol)

pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[EIP].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// File @openzeppelin/contracts/utils/introspection/ERC165.sol@v5.0.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/introspection/ERC165.sol)

pragma solidity ^0.8.20;

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 */
abstract contract ERC165 is IERC165 {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

// File @openzeppelin/contracts/access/AccessControl.sol@v5.0.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (access/AccessControl.sol)

pragma solidity ^0.8.20;

/**
 * @dev Contract module that allows children to implement role-based access
 * control mechanisms. This is a lightweight version that doesn't allow enumerating role
 * members except through off-chain means by accessing the contract event logs. Some
 * applications may benefit from on-chain enumerability, for those cases see
 * {AccessControlEnumerable}.
 *
 * Roles are referred to by their `bytes32` identifier. These should be exposed
 * in the external API and be unique. The best way to achieve this is by
 * using `public constant` hash digests:
 *
 * ```solidity
 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
 * ```
 *
 * Roles can be used to represent a set of permissions. To restrict access to a
 * function call, use {hasRole}:
 *
 * ```solidity
 * function foo() public {
 *     require(hasRole(MY_ROLE, msg.sender));
 *     ...
 * }
 * ```
 *
 * Roles can be granted and revoked dynamically via the {grantRole} and
 * {revokeRole} functions. Each role has an associated admin role, and only
 * accounts that have a role's admin role can call {grantRole} and {revokeRole}.
 *
 * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
 * that only accounts with this role will be able to grant or revoke other
 * roles. More complex role relationships can be created by using
 * {_setRoleAdmin}.
 *
 * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
 * grant and revoke this role. Extra precautions should be taken to secure
 * accounts that have been granted it. We recommend using {AccessControlDefaultAdminRules}
 * to enforce additional security measures for this role.
 */
abstract contract AccessControl is Context, IAccessControl, ERC165 {
    struct RoleData {
        mapping(address account => bool) hasRole;
        bytes32 adminRole;
    }

    mapping(bytes32 role => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /**
     * @dev Modifier that checks that an account has a specific role. Reverts
     * with an {AccessControlUnauthorizedAccount} error including the required role.
     */
    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override returns (bool) {
        return
            interfaceId == type(IAccessControl).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(
        bytes32 role,
        address account
    ) public view virtual returns (bool) {
        return _roles[role].hasRole[account];
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `_msgSender()`
     * is missing `role`. Overriding this function changes the behavior of the {onlyRole} modifier.
     */
    function _checkRole(bytes32 role) internal view virtual {
        _checkRole(role, _msgSender());
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `account`
     * is missing `role`.
     */
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert AccessControlUnauthorizedAccount(account, role);
        }
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view virtual returns (bytes32) {
        return _roles[role].adminRole;
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleGranted} event.
     */
    function grantRole(
        bytes32 role,
        address account
    ) public virtual onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(
        bytes32 role,
        address account
    ) public virtual onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     *
     * May emit a {RoleRevoked} event.
     */
    function renounceRole(
        bytes32 role,
        address callerConfirmation
    ) public virtual {
        if (callerConfirmation != _msgSender()) {
            revert AccessControlBadConfirmation();
        }

        _revokeRole(role, callerConfirmation);
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        bytes32 previousAdminRole = getRoleAdmin(role);
        _roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /**
     * @dev Attempts to grant `role` to `account` and returns a boolean indicating if `role` was granted.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleGranted} event.
     */
    function _grantRole(
        bytes32 role,
        address account
    ) internal virtual returns (bool) {
        if (!hasRole(role, account)) {
            _roles[role].hasRole[account] = true;
            emit RoleGranted(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Attempts to revoke `role` to `account` and returns a boolean indicating if `role` was revoked.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleRevoked} event.
     */
    function _revokeRole(
        bytes32 role,
        address account
    ) internal virtual returns (bool) {
        if (hasRole(role, account)) {
            _roles[role].hasRole[account] = false;
            emit RoleRevoked(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }
}

// File @openzeppelin/contracts/token/ERC721/IERC721.sol@v5.0.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC721/IERC721.sol)

pragma solidity ^0.8.20;

/**
 * @dev Required interface of an ERC721 compliant contract.
 */
interface IERC721 is IERC165 {
    /**
     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.
     */
    event Transfer(
        address indexed from,
        address indexed to,
        uint256 indexed tokenId
    );

    /**
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
     */
    event Approval(
        address indexed owner,
        address indexed approved,
        uint256 indexed tokenId
    );

    /**
     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.
     */
    event ApprovalForAll(
        address indexed owner,
        address indexed operator,
        bool approved
    );

    /**
     * @dev Returns the number of tokens in ``owner``'s account.
     */
    function balanceOf(address owner) external view returns (uint256 balance);

    /**
     * @dev Returns the owner of the `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function ownerOf(uint256 tokenId) external view returns (address owner);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon
     *   a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata data
    ) external;

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must have been allowed to move this token by either {approve} or
     *   {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon
     *   a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

    /**
     * @dev Transfers `tokenId` token from `from` to `to`.
     *
     * WARNING: Note that the caller is responsible to confirm that the recipient is capable of receiving ERC721
     * or else they may be permanently lost. Usage of {safeTransferFrom} prevents loss, though the caller must
     * understand this adds an external call which potentially creates a reentrancy vulnerability.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @dev Gives permission to `to` to transfer `tokenId` token to another account.
     * The approval is cleared when the token is transferred.
     *
     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the token or be an approved operator.
     * - `tokenId` must exist.
     *
     * Emits an {Approval} event.
     */
    function approve(address to, uint256 tokenId) external;

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     *
     * Requirements:
     *
     * - The `operator` cannot be the address zero.
     *
     * Emits an {ApprovalForAll} event.
     */
    function setApprovalForAll(address operator, bool approved) external;

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(
        uint256 tokenId
    ) external view returns (address operator);

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(
        address owner,
        address operator
    ) external view returns (bool);
}

// File @openzeppelin/contracts/token/ERC20/IERC20.sol@v5.0.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/IERC20.sol)

pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );

    /**
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(
        address owner,
        address spender
    ) external view returns (uint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address from,
        address to,
        uint256 value
    ) external returns (bool);
}

// File @openzeppelin/contracts/token/ERC721/IERC721Receiver.sol@v5.0.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC721/IERC721Receiver.sol)

pragma solidity ^0.8.20;

/**
 * @title ERC721 token receiver interface
 * @dev Interface for any contract that wants to support safeTransfers
 * from ERC721 asset contracts.
 */
interface IERC721Receiver {
    /**
     * @dev Whenever an {IERC721} `tokenId` token is transferred to this contract via {IERC721-safeTransferFrom}
     * by `operator` from `from`, this function is called.
     *
     * It must return its Solidity selector to confirm the token transfer.
     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be
     * reverted.
     *
     * The selector can be obtained in Solidity with `IERC721Receiver.onERC721Received.selector`.
     */
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

// File @openzeppelin/contracts/utils/math/Math.sol@v5.0.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/math/Math.sol)

pragma solidity ^0.8.20;

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    /**
     * @dev Muldiv operation overflow.
     */
    error MathOverflowedMulDiv();

    enum Rounding {
        Floor, // Toward negative infinity
        Ceil, // Toward positive infinity
        Trunc, // Toward zero
        Expand // Away from zero
    }

    /**
     * @dev Returns the addition of two unsigned integers, with an overflow flag.
     */
    function tryAdd(
        uint256 a,
        uint256 b
    ) internal pure returns (bool, uint256) {
        unchecked {
            uint256 c = a + b;
            if (c < a) return (false, 0);
            return (true, c);
        }
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, with an overflow flag.
     */
    function trySub(
        uint256 a,
        uint256 b
    ) internal pure returns (bool, uint256) {
        unchecked {
            if (b > a) return (false, 0);
            return (true, a - b);
        }
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.
     */
    function tryMul(
        uint256 a,
        uint256 b
    ) internal pure returns (bool, uint256) {
        unchecked {
            // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
            // benefit is lost if 'b' is also tested.
            // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
            if (a == 0) return (true, 0);
            uint256 c = a * b;
            if (c / a != b) return (false, 0);
            return (true, c);
        }
    }

    /**
     * @dev Returns the division of two unsigned integers, with a division by zero flag.
     */
    function tryDiv(
        uint256 a,
        uint256 b
    ) internal pure returns (bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a / b);
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.
     */
    function tryMod(
        uint256 a,
        uint256 b
    ) internal pure returns (bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a % b);
        }
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b) / 2 can overflow.
        return (a & b) + (a ^ b) / 2;
    }

    /**
     * @dev Returns the ceiling of the division of two numbers.
     *
     * This differs from standard division with `/` in that it rounds towards infinity instead
     * of rounding towards zero.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) {
            // Guarantee the same behavior as in a regular Solidity division.
            return a / b;
        }

        // (a + b - 1) / b can overflow on addition, so we distribute.
        return a == 0 ? 0 : (a - 1) / b + 1;
    }

    /**
     * @notice Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or
     * denominator == 0.
     * @dev Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv) with further edits by
     * Uniswap Labs also under MIT license.
     */
    function mulDiv(
        uint256 x,
        uint256 y,
        uint256 denominator
    ) internal pure returns (uint256 result) {
        unchecked {
            // 512-bit multiply [prod1 prod0] = x * y. Compute the product mod 2^256 and mod 2^256 - 1, then use
            // use the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
            // variables such that product = prod1 * 2^256 + prod0.
            uint256 prod0 = x * y; // Least significant 256 bits of the product
            uint256 prod1; // Most significant 256 bits of the product
            assembly {
                let mm := mulmod(x, y, not(0))
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))
            }

            // Handle non-overflow cases, 256 by 256 division.
            if (prod1 == 0) {
                // Solidity will revert if denominator == 0, unlike the div opcode on its own.
                // The surrounding unchecked block does not change this fact.
                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.
                return prod0 / denominator;
            }

            // Make sure the result is less than 2^256. Also prevents denominator == 0.
            if (denominator <= prod1) {
                revert MathOverflowedMulDiv();
            }

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [prod1 prod0].
            uint256 remainder;
            assembly {
                // Compute remainder using mulmod.
                remainder := mulmod(x, y, denominator)

                // Subtract 256 bit number from 512 bit number.
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator.
            // Always >= 1. See https://cs.stackexchange.com/q/138556/92363.

            uint256 twos = denominator & (0 - denominator);
            assembly {
                // Divide denominator by twos.
                denominator := div(denominator, twos)

                // Divide [prod1 prod0] by twos.
                prod0 := div(prod0, twos)

                // Flip twos such that it is 2^256 / twos. If twos is zero, then it becomes one.
                twos := add(div(sub(0, twos), twos), 1)
            }

            // Shift in bits from prod1 into prod0.
            prod0 |= prod1 * twos;

            // Invert denominator mod 2^256. Now that denominator is an odd number, it has an inverse modulo 2^256 such
            // that denominator * inv = 1 mod 2^256. Compute the inverse by starting with a seed that is correct for
            // four bits. That is, denominator * inv = 1 mod 2^4.
            uint256 inverse = (3 * denominator) ^ 2;

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also
            // works in modular arithmetic, doubling the correct bits in each step.
            inverse *= 2 - denominator * inverse; // inverse mod 2^8
            inverse *= 2 - denominator * inverse; // inverse mod 2^16
            inverse *= 2 - denominator * inverse; // inverse mod 2^32
            inverse *= 2 - denominator * inverse; // inverse mod 2^64
            inverse *= 2 - denominator * inverse; // inverse mod 2^128
            inverse *= 2 - denominator * inverse; // inverse mod 2^256

            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.
            // This will give us the correct result modulo 2^256. Since the preconditions guarantee that the outcome is
            // less than 2^256, this is the final result. We don't need to compute the high bits of the result and prod1
            // is no longer required.
            result = prod0 * inverse;
            return result;
        }
    }

    /**
     * @notice Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(
        uint256 x,
        uint256 y,
        uint256 denominator,
        Rounding rounding
    ) internal pure returns (uint256) {
        uint256 result = mulDiv(x, y, denominator);
        if (unsignedRoundsUp(rounding) && mulmod(x, y, denominator) > 0) {
            result += 1;
        }
        return result;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded
     * towards zero.
     *
     * Inspired by Henry S. Warren, Jr.'s "Hacker's Delight" (Chapter 11).
     */
    function sqrt(uint256 a) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }

        // For our first guess, we get the biggest power of 2 which is smaller than the square root of the target.
        //
        // We know that the "msb" (most significant bit) of our target number `a` is a power of 2 such that we have
        // `msb(a) <= a < 2*msb(a)`. This value can be written `msb(a)=2**k` with `k=log2(a)`.
        //
        // This can be rewritten `2**log2(a) <= a < 2**(log2(a) + 1)`
        // 鈫?`sqrt(2**k) <= sqrt(a) < sqrt(2**(k+1))`
        // 鈫?`2**(k/2) <= sqrt(a) < 2**((k+1)/2) <= 2**(k/2 + 1)`
        //
        // Consequently, `2**(log2(a) / 2)` is a good first approximation of `sqrt(a)` with at least 1 correct bit.
        uint256 result = 1 << (log2(a) >> 1);

        // At this point `result` is an estimation with one bit of precision. We know the true value is a uint128,
        // since it is the square root of a uint256. Newton's method converges quadratically (precision doubles at
        // every iteration). We thus need at most 7 iteration to turn our partial result with one bit of precision
        // into the expected uint128 result.
        unchecked {
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            return min(result, a / result);
        }
    }

    /**
     * @notice Calculates sqrt(a), following the selected rounding direction.
     */
    function sqrt(
        uint256 a,
        Rounding rounding
    ) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return
                result +
                (unsignedRoundsUp(rounding) && result * result < a ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 2 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log2(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 128;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 64;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 32;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 16;
            }
            if (value >> 8 > 0) {
                value >>= 8;
                result += 8;
            }
            if (value >> 4 > 0) {
                value >>= 4;
                result += 4;
            }
            if (value >> 2 > 0) {
                value >>= 2;
                result += 2;
            }
            if (value >> 1 > 0) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(
        uint256 value,
        Rounding rounding
    ) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return
                result +
                (unsignedRoundsUp(rounding) && 1 << result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 10 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(
        uint256 value,
        Rounding rounding
    ) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return
                result +
                (unsignedRoundsUp(rounding) && 10 ** result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 256 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     *
     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.
     */
    function log256(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 16;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 8;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 4;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 2;
            }
            if (value >> 8 > 0) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log256(
        uint256 value,
        Rounding rounding
    ) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return
                result +
                (
                    unsignedRoundsUp(rounding) && 1 << (result << 3) < value
                        ? 1
                        : 0
                );
        }
    }

    /**
     * @dev Returns whether a provided rounding mode is considered rounding up for unsigned integers.
     */
    function unsignedRoundsUp(Rounding rounding) internal pure returns (bool) {
        return uint8(rounding) % 2 == 1;
    }
}

// File contracts/IConverter.sol

interface IConverter {
    function convertToken(
        uint256 gameId,
        address receiver,
        uint256 amount
    ) external returns (bool beenDone);
}

// File contracts/IVault.sol

interface IVault {
    function checkSysTokenFundsReceive(uint256 receiveAmount) external;
}

// File contracts/3_Fromo.sol

pragma solidity ^0.8.24;

// Original pragma directive: pragma experimental ABIEncoderV2

contract Fromo is AccessControl {
    event GameCreated(
        uint256 gameId,
        address indexed NftPrincipal,
        address indexed NftAddress,
        uint256 nftId
    );

    event GameJoined(
        uint256 indexed GameId,
        address indexed Player,
        uint256 _keyAmount
    );

    event NftRetrieved(uint256 gameId, address indexed RetrieveAddress);

    event ClaimKeyBonus(
        uint256 indexed GameId,
        address indexed Player,
        uint256 bonusAmount
    );

    event WithdrawLastPlayerPrize(
        uint256 gameId,
        address indexed Winner,
        uint256 prize
    );

    event WithdrawSaleRevenue(
        uint256 gameId,
        address indexed Principal,
        uint256 pureSalesRevenue
    );

    enum gameState {
        NotStart,
        Playing,
        Finished
    }

    struct Game {
        uint256 accHeightPerKey1e18;
        uint256 nftId;
        address nftAddress;
        uint96 totalKeyMinted;
        address principal;
        uint96 startTimestamp;
        address lastPlayer;
        uint96 keyPrice;
        address mostKeyHolder;
    }

    struct GameInfo {
        gameState state;
        address nftAddress;
        uint256 nftId;
        address principal;
        uint128 startTimestamp;
        uint128 endTimestamp;
        uint128 keyPrice;
        uint96 totalKeyMinted;
        uint256 salesRevenue;
        address mostKeyHolder;
        address lastPlayer;
    }

    mapping(address => mapping(uint256 => uint256)) accountToGameIdToKeyAmount;

    mapping(address => mapping(uint256 => uint256))
        public accountToGameIdToRealizedBonus;
    mapping(address => mapping(uint256 => uint256))
        public accountToGameIdToPerKeyHeight1e18;
    Game[] public games;

    IERC20 public immutable sysTokenContract;
    IVault public vaultContract;
    IConverter public converterContract;

    uint256 immutable sysTokenDecimalsValue = 1e18;
    bytes32 public constant GAME_CREATOR_ROLE =
        0x0000000000000000000000000000000000000000000000000000000000000001;

    constructor(address sysTokenAddress, address vaultAddress) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        sysTokenContract = IERC20(sysTokenAddress);
        vaultContract = IVault(vaultAddress);
    }

    function updateVault(
        address newVaultAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        vaultContract = IVault(newVaultAddress);
    }

    function updateConverter(
        address newConverterAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        converterContract = IConverter(newConverterAddress);
    }

    modifier checkNftWhiteList(address nftContractAddress) {
        if (useNftContractWhiteList) {
            require(
                nftContractWhiteList[nftContractAddress],
                "FR: NFT not permit"
            );
        }
        _;
    }

    function totalGames() external view returns (uint256 gameCount) {
        gameCount = games.length;
    }

    uint256 public gameStartDeny = 10 minutes;

    function setGameStartDeny(
        uint256 newDeny
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        gameStartDeny = newDeny;
    }

    uint128 public constant GAME_END_DENY = 1 days - 30;

    mapping(address => bool) public nftContractWhiteList;
    bool public useNftContractWhiteList;

    function switchWL(bool turnOnWL) external onlyRole(DEFAULT_ADMIN_ROLE) {
        useNftContractWhiteList = turnOnWL;
    }

    function setWL(
        address[] memory nftContractAddress,
        bool inWhiteList
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        for (uint i = 0; i < nftContractAddress.length; i++) {
            nftContractWhiteList[nftContractAddress[i]] = inWhiteList;
        }
    }

    uint256 public sysTotalKeyMinted;
    uint256 public totalKeyMintedBias;
    uint256 public baseKeyPrice = 0.01 gwei;

    function setBias(uint256 newBias) external onlyRole(DEFAULT_ADMIN_ROLE) {
        totalKeyMintedBias = newBias;
    }

    function createGameDirectly(
        address nftAddress,
        uint256 nftId,
        uint96 startTimestamp
    ) external onlyRole(GAME_CREATOR_ROLE) {
        _newGame(nftAddress, nftId, startTimestamp);
    }

    function getKeyPrice(
        uint256 givenSysTotalKeyMinted
    ) public view returns (uint96 keyPrice) {
        uint256 _increasePrice = Math.sqrt(
            Math.sqrt((givenSysTotalKeyMinted - totalKeyMintedBias) * 1e36)
        ) / 1000;
        keyPrice = uint96((baseKeyPrice + _increasePrice) * 1 gwei);
    }

    function _getKeyPrice() internal view returns (uint96 keyPrice) {
        keyPrice = getKeyPrice(sysTotalKeyMinted);
    }

    modifier requireGameNotstart(uint256 gameId) {
        gameState _state = _getGameStateOfGameId(gameId);

        require(_state == gameState.NotStart, "FR: Not before start");
        _;
    }

    modifier requireGamePlaying(uint256 gameId) {
        gameState _state = _getGameStateOfGameId(gameId);
        if (_state == gameState.NotStart) {
            revert("FR: Not start yet");
        } else if (_state == gameState.Finished) {
            revert("FR: Game finished");
        }
        _;
    }

    modifier requireGameFinished(uint256 gameId) {
        gameState _state = _getGameStateOfGameId(gameId);

        require(_state == gameState.Finished, "FR: Not finished yet");
        _;
    }

    modifier onlyPrincipal(uint256 gameId) {
        Game storage _game = games[gameId];
        require(msg.sender == _game.principal, "FR: Only principal");
        _;
    }

    function buyKeyLimit(uint256 gameId) public view returns (uint256 limit) {
        limit = ((games[gameId].totalKeyMinted / 10) + 1);
    }

    function _newGame(
        address nftAddress,
        uint256 nftId,
        uint96 startTimestamp
    ) internal checkNftWhiteList(nftAddress) {
        address _nftPrincipal = msg.sender;

        IERC721 _nftcontract = IERC721(nftAddress);
        _nftcontract.safeTransferFrom(_nftPrincipal, address(this), nftId);

        uint256 _gameId = games.length;
        games.push(
            Game({
                accHeightPerKey1e18: 0,
                nftId: nftId,
                nftAddress: nftAddress,
                totalKeyMinted: 1,
                principal: _nftPrincipal,
                startTimestamp: startTimestamp,
                lastPlayer: _nftPrincipal,
                keyPrice: _getKeyPrice(),
                mostKeyHolder: _nftPrincipal
            })
        );

        accountToGameIdToKeyAmount[_nftPrincipal][_gameId] = 1;

        emit GameCreated(_gameId, _nftPrincipal, nftAddress, nftId);
    }

    function _realizeBonus(uint256 gameId, address player) internal {
        uint256 _accHeightPerKey1e18 = games[gameId].accHeightPerKey1e18;

        accountToGameIdToRealizedBonus[player][gameId] += _getUnrealizedBonusOf(
            gameId,
            player
        );

        accountToGameIdToPerKeyHeight1e18[player][
            gameId
        ] = _accHeightPerKey1e18;
    }

    function purchaseKeyOfGameId(
        uint256 gameId
    ) external payable requireGamePlaying(gameId) {
        Game storage _game = games[gameId];
        address _player = msg.sender;

        uint256 _newSalesRevenue = msg.value;
        require(
            _newSalesRevenue >= _game.keyPrice &&
                _newSalesRevenue % _game.keyPrice == 0,
            "FR: keyPrice Error"
        );

        uint256 _keyAmount = _newSalesRevenue / _game.keyPrice;
        require(_keyAmount <= buyKeyLimit(gameId), "FL-Buy key: OUT OF LIMIT");

        _game.lastPlayer = _player;

        _game.accHeightPerKey1e18 +=
            ((_newSalesRevenue * 1e18) / 5) /
            uint256(_game.totalKeyMinted);

        _realizeBonus(gameId, _player);

        accountToGameIdToKeyAmount[_player][gameId] += _keyAmount;

        _game.totalKeyMinted += uint96(_keyAmount);

        sysTotalKeyMinted += _keyAmount;

        uint256 _currentMostHoldingAmount = accountToGameIdToKeyAmount[
            _game.mostKeyHolder
        ][gameId];
        uint256 _playerHoldingAmount = accountToGameIdToKeyAmount[_player][
            gameId
        ];
        if (_playerHoldingAmount > _currentMostHoldingAmount) {
            _game.mostKeyHolder = _player;
        }

        emit GameJoined(gameId, _player, _keyAmount);
    }

    function retrieveNft(uint256 gameId) external requireGameFinished(gameId) {
        Game storage _game = games[gameId];
        address _retrieveAddress = msg.sender;
        uint256 _now = uint256(block.timestamp);
        uint256 _endTimestamp = _getGameEndTimestampOfGameId(gameId);

        if (_now < _endTimestamp + 1 days) {
            if (_game.mostKeyHolder == address(0)) {
                revert("FR: Already Retrieved");
            }
            require(
                _retrieveAddress == _game.mostKeyHolder,
                "FR: Only Most Key Holder"
            );

            delete _game.mostKeyHolder;
        }

        uint256 _nftPriceBySysToken = (uint256(
            _game.totalKeyMinted * sysTokenDecimalsValue
        ) * 11) / 10;

        sysTokenContract.transferFrom(
            _retrieveAddress,
            address(vaultContract),
            _nftPriceBySysToken
        );

        vaultContract.checkSysTokenFundsReceive(_nftPriceBySysToken);

        IERC721 _nftcontract = IERC721(_game.nftAddress);

        _nftcontract.safeTransferFrom(
            address(this),
            _retrieveAddress,
            _game.nftId
        );

        delete _game.nftAddress;
        delete _game.nftId;
        emit NftRetrieved(gameId, _retrieveAddress);
    }

    function withdrawLastplayerPrize(uint256[] calldata gameIds) external {
        for (uint256 i = 0; i < gameIds.length; i++) {
            _withdrawLastPlayerPrize(gameIds[i]);
        }
    }

    function claimBonus(uint256[] calldata gameIds, address player) external {
        for (uint256 i = 0; i < gameIds.length; i++) {
            _claimBonus(gameIds[i], player);
        }
    }

    function withdrawSaleRevenue(uint256[] calldata gameIds) external {
        for (uint256 i = 0; i < gameIds.length; i++) {
            _withdrawSaleRevenue(gameIds[i]);
        }
    }

    function convertKeyToToken(
        uint256[] calldata gameIds,
        address tokenReceiver
    ) external {
        for (uint256 i = 0; i < gameIds.length; i++) {
            _convertKeyToToken(gameIds[i], tokenReceiver);
        }
    }

    function getGameInfoOfGameIds(
        uint256[] calldata gameIds
    ) external view returns (GameInfo[] memory gameInfos) {
        GameInfo[] memory cacheA = new GameInfo[](gameIds.length);
        for (uint256 i = 0; i < gameIds.length; i++) {
            Game storage _game = games[gameIds[i]];
            cacheA[i] = GameInfo(
                _getGameStateOfGameId(gameIds[i]),
                _game.nftAddress,
                _game.nftId,
                _game.principal,
                _game.startTimestamp,
                _getGameEndTimestampOfGameId(gameIds[i]),
                _game.keyPrice,
                _game.totalKeyMinted,
                _getSalesRevenueOf(gameIds[i]),
                _game.mostKeyHolder,
                _game.lastPlayer
            );
        }
        return cacheA;
    }

    function getGameStateOfGameIds(
        uint256[] calldata gameIds
    ) external view returns (gameState[] memory states) {
        gameState[] memory cacheA = new gameState[](gameIds.length);
        for (uint256 i = 0; i < gameIds.length; i++) {
            cacheA[i] = _getGameStateOfGameId(gameIds[i]);
        }

        return cacheA;
    }

    function getPlayerStateOfGameIds(
        address player,
        uint256[] calldata gameIds
    )
        external
        view
        returns (
            uint256[] memory unclaimBonusList,
            uint256[] memory keyAmountList
        )
    {
        uint256[] memory cacheA = new uint256[](gameIds.length);
        uint256[] memory cachaB = new uint256[](gameIds.length);

        for (uint256 i = 0; i < gameIds.length; i++) {
            cacheA[i] = _getUnclaimBonusOf(gameIds[i], player);
            cachaB[i] = accountToGameIdToKeyAmount[player][gameIds[i]];
        }

        return (cacheA, cachaB);
    }

    function getGameEndTimestampOfGameIds(
        uint256[] calldata gameIds
    ) external view returns (uint256[] memory gameEndTimestamps) {
        uint256[] memory cacheA = new uint256[](gameIds.length);
        for (uint256 i = 0; i < gameIds.length; i++) {
            cacheA[i] = uint256(_getGameEndTimestampOfGameId(gameIds[i]));
        }
        return cacheA;
    }

    function getGameEndTimeCountDowns(
        uint256[] calldata gameIds
    ) external view returns (uint128[] memory countDowns) {
        uint128[] memory cacheA = new uint128[](gameIds.length);
        uint128 _now = uint128(block.timestamp);
        for (uint256 i = 0; i < gameIds.length; i++) {
            uint128 _endTimestamp = _getGameEndTimestampOfGameId(gameIds[i]);
            cacheA[i] = _endTimestamp > _now ? _endTimestamp - _now : 0;
        }
        return cacheA;
    }

    function _getSalesRevenueOf(
        uint256 gameId
    ) internal view returns (uint256 salesRevenue) {
        salesRevenue =
            games[gameId].keyPrice *
            (games[gameId].totalKeyMinted - 1);
    }

    function _getUnrealizedBonusOf(
        uint256 gameId,
        address player
    ) internal view returns (uint256 _unRealizedAmout) {
        Game storage _game = games[gameId];

        _unRealizedAmout =
            ((_game.accHeightPerKey1e18 -
                accountToGameIdToPerKeyHeight1e18[player][gameId]) *
                accountToGameIdToKeyAmount[player][gameId]) /
            1e18;
    }

    function _getUnclaimBonusOf(
        uint256 gameId,
        address player
    ) internal view returns (uint256 unclaimAmount) {
        uint256 _unRealizedAmout = _getUnrealizedBonusOf(gameId, player);
        uint256 _realizedAmount = accountToGameIdToRealizedBonus[player][
            gameId
        ];
        unclaimAmount = _unRealizedAmout + _realizedAmount;
    }

    function _getGameStateOfGameId(
        uint256 gameId
    ) internal view returns (gameState state) {
        Game storage _game = games[gameId];
        uint128 _now = uint128(block.timestamp);
        if (_now < _game.startTimestamp) {
            return gameState.NotStart;
        } else {
            if (_now < _getGameEndTimestampOfGameId(gameId)) {
                return gameState.Playing;
            } else {
                return gameState.Finished;
            }
        }
    }

    function _getGameEndTimestampOfGameId(
        uint256 gameId
    ) internal view returns (uint128 gameEndTimestamp) {
        Game storage _game = games[gameId];
        gameEndTimestamp =
            _game.startTimestamp +
            (_game.totalKeyMinted * 30) +
            GAME_END_DENY;
    }

    function _withdrawLastPlayerPrize(
        uint256 gameId
    ) internal requireGameFinished(gameId) {
        Game storage _game = games[gameId];
        if (_game.lastPlayer != address(0)) {
            address _lastPlayer = _game.lastPlayer;

            delete _game.lastPlayer;

            uint256 _prize = _getSalesRevenueOf(gameId) / 5;
            payable(_lastPlayer).transfer(_prize);

            emit WithdrawLastPlayerPrize(gameId, _lastPlayer, _prize);

            payable(address(vaultContract)).transfer(_prize / 2);
        }
    }

    function _withdrawSaleRevenue(
        uint256 gameId
    ) internal requireGameFinished(gameId) {
        Game storage _game = games[gameId];
        if (_game.principal != address(0)) {
            address _principal = _game.principal;

            delete _game.principal;

            uint256 _pureSalesRevenue = _getSalesRevenueOf(gameId) / 2;
            payable(_principal).transfer(_pureSalesRevenue);

            emit WithdrawSaleRevenue(gameId, _principal, _pureSalesRevenue);
        }
    }

    function _claimBonus(uint256 gameId, address player) internal {
        uint256 _bonus = _getUnclaimBonusOf(gameId, player);
        Game storage _game = games[gameId];

        accountToGameIdToPerKeyHeight1e18[player][gameId] = _game
            .accHeightPerKey1e18;

        accountToGameIdToRealizedBonus[player][gameId] = 0;

        payable(player).transfer(_bonus);

        emit ClaimKeyBonus(gameId, player, _bonus);
    }

    function _convertKeyToToken(
        uint256 gameId,
        address tokenReceiver
    ) internal requireGameFinished(gameId) {
        _realizeBonus(gameId, tokenReceiver);

        uint256 _unConvertTokensAmount = accountToGameIdToKeyAmount[
            tokenReceiver
        ][gameId];

        if (_unConvertTokensAmount < 1e18) {
            accountToGameIdToKeyAmount[tokenReceiver][
                gameId
            ] *= sysTokenDecimalsValue;

            bool done = converterContract.convertToken(
                gameId,
                tokenReceiver,
                _unConvertTokensAmount * sysTokenDecimalsValue
            );
        }
    }

    function onERC721Received(
        address msgSender,
        address from,
        uint256 tokenId,
        bytes memory data
    ) external pure returns (bytes4 selector) {
        selector = IERC721Receiver.onERC721Received.selector;
    }
}

contract BidFromo is Fromo {
    constructor(
        address sysTokenAddress,
        address vaultAddress,
        uint96 cycleLength,
        uint32 timeRatioBasedOnCycle,
        uint96 bidStartTimePoint
    ) Fromo(sysTokenAddress, vaultAddress) {
        bidRoundInfo.cycleLength = cycleLength;
        bidRoundInfo.timeRatioBasedOnCycle = timeRatioBasedOnCycle;
        bidRoundInfo.bidStartTimePoint = bidStartTimePoint;
    }

    /** TODOs:
     * 鍦ㄨ繖閲岀紪鍐欑郴鍒楁媿鍗栧拰閴存潈鍒涘缓game鐨勫姛鑳斤紝灏咶romo鐨刵ewGame鍐呴儴鍖?     * 鍦ㄨ繖閲屽啓澶栭儴璋冪敤鐨刵ewGame
     *
     *
     *
     */

    struct BidRoundInfo {
        address bidWinner;
        uint96 cycleLength;
        uint128 lastBidId;
        uint96 bidStartTimePoint;
        uint32 timeRatioBasedOnCycle;
    }

    struct BidderInfo {
        uint128 lastBidId;
        uint256 bids;
        uint256 sysTokenBalance;
    }

    mapping(address => BidderInfo) bidderInfos;

    BidRoundInfo public bidRoundInfo;

    event NewBids(address indexed Bidder, uint256 amount, uint256 bidId);
    event SettleBids(address indexed BidWinner, uint256 amount, uint256 bidId);

    function getTimeBasedCurrentBidId()
        public
        view
        returns (uint128 currentBidId)
    {
        uint256 _now = block.timestamp;
        uint256 dTime = _now - bidRoundInfo.bidStartTimePoint;

        currentBidId = uint128(dTime / bidRoundInfo.cycleLength);
    }

    function _settleWinnerBids() internal {
        if (bidRoundInfo.bidWinner != address(0)) {
            address _bidWinner = bidRoundInfo.bidWinner;
            delete bidRoundInfo.bidWinner;

            BidderInfo storage _BI = bidderInfos[_bidWinner];
            _BI.sysTokenBalance -= _BI.bids;

            sysTokenContract.transfer(address(vaultContract), _BI.bids);
            emit SettleBids(_bidWinner, _BI.bids, _BI.lastBidId);
        }
    }

    function checkAndUpdateLastBidId() public {
        if (bidRoundInfo.lastBidId != getTimeBasedCurrentBidId()) {
            bidRoundInfo.lastBidId = getTimeBasedCurrentBidId();

            _settleWinnerBids();
        }
    }

    enum LandBidState {
        Bidding,
        Creating
    }

    function getBidState() public view returns (LandBidState state) {
        uint256 _now = block.timestamp;
        uint256 dTime = _now - bidRoundInfo.bidStartTimePoint;
        if (
            dTime % bidRoundInfo.cycleLength >
            bidRoundInfo.timeRatioBasedOnCycle
        ) {
            state = LandBidState.Creating;
        } else {
            state = LandBidState.Bidding;
        }
    }

    modifier checkAvaiableTimeToBid() {
        require(
            getBidState() == LandBidState.Bidding,
            "BFR: Not in bidding phase"
        );
        _;
    }

    modifier checkIsAvaiableToCreateNewGame() {
        require(
            getBidState() == LandBidState.Creating,
            "BFR: Not in creating phase"
        );

        address _msgSender = msg.sender;
        require(
            _msgSender == bidRoundInfo.bidWinner,
            "BFR: Not call by winner"
        );
        _;
    }

    function keepBidIdAndUpdateCycle(
        uint96 newCycleLength
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 _now = block.timestamp;
        uint256 dTime = _now - bidRoundInfo.bidStartTimePoint;

        uint256 _numerator = dTime % bidRoundInfo.cycleLength;

        uint128 _currentBidId = getTimeBasedCurrentBidId();
        uint256 _scaledNumerator = (newCycleLength * _numerator) /
            bidRoundInfo.cycleLength;
        bidRoundInfo.bidStartTimePoint = uint96(
            _now - (_currentBidId * newCycleLength + _scaledNumerator)
        );

        bidRoundInfo.timeRatioBasedOnCycle = uint32(
            (newCycleLength * bidRoundInfo.timeRatioBasedOnCycle) /
                bidRoundInfo.cycleLength
        );

        bidRoundInfo.cycleLength = newCycleLength;
    }

    function updateBidStartTimePoint(
        uint96 newBidStartTimePoint
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        bidRoundInfo.bidStartTimePoint = newBidStartTimePoint;
    }

    bool public isPaused;
    modifier checkIsPaused() {
        require(!isPaused, "BFR: Bid Paused");
        _;
    }

    function setPaused(bool newIsPaused) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            getBidState() == LandBidState.Creating,
            "BFR: Not in creating phase"
        );
        isPaused = newIsPaused;
    }

    function getNextRoundGameStartTimestamp()
        public
        view
        returns (uint96 startTimestamp)
    {
        startTimestamp = uint96(
            (getTimeBasedCurrentBidId() + 1) *
                bidRoundInfo.cycleLength +
                bidRoundInfo.bidStartTimePoint
        );
    }

    function getBidsOf(address bidder) public view returns (uint256 bids) {
        BidderInfo storage _BI = bidderInfos[bidder];

        if (
            _BI.lastBidId == getTimeBasedCurrentBidId() &&
            getBidState() == LandBidState.Bidding
        ) {
            bids = _BI.bids;
        } else if (bidder == bidRoundInfo.bidWinner) {
            bids = _BI.bids;
        } else {
            bids = 0;
        }
    }

    function getWithdrawableTokenAmountOf(
        address bidder
    ) public view returns (uint256 amount) {
        BidderInfo storage _BI = bidderInfos[bidder];

        amount = _BI.sysTokenBalance - getBidsOf(bidder);
    }

    function getBidderInfoOf(
        address bidder
    )
        public
        view
        returns (
            uint128 lastBidId,
            uint256 sysTokenBalance,
            uint256 bids,
            uint256 withdrawableAmount
        )
    {
        BidderInfo storage _bi = bidderInfos[bidder];
        lastBidId = _bi.lastBidId;
        sysTokenBalance = _bi.sysTokenBalance;
        bids = getBidsOf(bidder);
        withdrawableAmount = getWithdrawableTokenAmountOf(bidder);
    }

    function depositBidToken(uint256 amount) external {
        address _msgSender = msg.sender;
        BidderInfo storage _BI = bidderInfos[_msgSender];

        sysTokenContract.transferFrom(_msgSender, address(this), amount);

        _BI.sysTokenBalance += amount;
    }

    function withdrawBidToken(uint256 amount) external {
        checkAndUpdateLastBidId();
        address _msgSender = msg.sender;
        BidderInfo storage _BI = bidderInfos[_msgSender];
        require(
            getWithdrawableTokenAmountOf(_msgSender) >= amount,
            "BFR: Insufficient withdrawable balance"
        );
        _BI.sysTokenBalance -= amount;

        sysTokenContract.transfer(_msgSender, amount);
    }

    function bidLand(
        uint256 newBids
    ) external checkAvaiableTimeToBid checkIsPaused {
        checkAndUpdateLastBidId();
        address _bidder = msg.sender;

        BidderInfo storage _BI = bidderInfos[_bidder];

        if (newBids > _BI.sysTokenBalance) revert("BFR: Bids out of balance");

        uint256 _mostBids = bidderInfos[bidRoundInfo.bidWinner].bids;

        require(newBids > _mostBids + 1e14, "BFR: Bids low");

        bidRoundInfo.bidWinner = _bidder;

        _BI.lastBidId = getTimeBasedCurrentBidId();
        _BI.bids = newBids;

        emit NewBids(_bidder, newBids, _BI.lastBidId);
    }

    function newGame(
        address nftAddress,
        uint256 nftId
    ) external checkIsAvaiableToCreateNewGame {
        _settleWinnerBids();

        _newGame(nftAddress, nftId, getNextRoundGameStartTimestamp());
    }
}
// 0x628fa547647B4B8D826fA2962aaec526c1DAD6d7