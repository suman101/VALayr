// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title UpgradeableVault — Stage 2 multi-contract proxy pattern task.
/// @dev Vulnerable: Transparent proxy with storage collision + upgrade attack surface.
/// @notice Introduced in Month 3. Requires multi-contract exploit reasoning.

/// ── Proxy Contract ──────────────────────────────────────────────────────────
contract TransparentProxy {
    // EIP-1967 implementation slot
    bytes32 private constant _IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    // EIP-1967 admin slot
    bytes32 private constant _ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    constructor(address implementation, address admin_) {
        _setImplementation(implementation);
        _setAdmin(admin_);
    }

    // Admin functions (should be protected but have subtle bugs)
    function upgradeTo(address newImpl) external {
        require(msg.sender == _getAdmin(), "Not admin");
        _setImplementation(newImpl);
    }

    /// @dev VULNERABILITY: admin() is callable by anyone and leaks admin address.
    /// Combined with implementation check, enables targeted phishing.
    function admin() external view returns (address) {
        return _getAdmin();
    }

    /// @dev VULNERABILITY: No check that new implementation has code.
    /// Upgrading to EOA or selfdestruct'd address brinks proxy.
    function upgradeToAndCall(address newImpl, bytes calldata data) external {
        require(msg.sender == _getAdmin(), "Not admin");
        _setImplementation(newImpl);
        (bool ok, ) = newImpl.delegatecall(data);
        require(ok, "Init failed");
    }

    fallback() external payable {
        address impl = _getImplementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    receive() external payable {}

    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = _IMPL_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setImplementation(address impl) internal {
        bytes32 slot = _IMPL_SLOT;
        assembly {
            sstore(slot, impl)
        }
    }

    function _getAdmin() internal view returns (address a) {
        bytes32 slot = _ADMIN_SLOT;
        assembly {
            a := sload(slot)
        }
    }

    function _setAdmin(address a) internal {
        bytes32 slot = _ADMIN_SLOT;
        assembly {
            sstore(slot, a)
        }
    }
}

/// ── Implementation V1 ───────────────────────────────────────────────────────
contract VaultV1 {
    // Storage layout MUST match proxy expectations
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;
    address public governance;
    bool public initialized;

    function initialize(address _governance) external {
        /// @dev VULNERABILITY: No initializer guard — can be re-initialized.
        governance = _governance;
        initialized = true;
    }

    function deposit() external payable {
        require(initialized, "Not initialized");
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient");
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Failed");
    }

    function emergencyWithdraw() external {
        require(msg.sender == governance, "Not governance");
        (bool ok, ) = governance.call{value: address(this).balance}("");
        require(ok, "Failed");
    }
}

/// ── Implementation V2 (Upgrade target with hidden bug) ──────────────────────
contract VaultV2 {
    // Storage layout matches V1
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;
    address public governance;
    bool public initialized;

    // New storage in V2
    mapping(address => bool) public whitelisted;
    uint256 public feeRate; // basis points

    function initialize(address _governance) external {
        governance = _governance;
        initialized = true;
    }

    function deposit() external payable {
        require(initialized, "Not initialized");
        uint256 fee = (msg.value * feeRate) / 10000;
        deposits[msg.sender] += msg.value - fee;
        totalDeposits += msg.value - fee;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient");
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Failed");
    }

    /// @dev VULNERABILITY: setFeeRate has no upper bound check.
    /// Fee rate can be set to > 10000 (>100%), causing underflow in deposit.
    function setFeeRate(uint256 _rate) external {
        require(msg.sender == governance, "Not governance");
        feeRate = _rate;
    }

    function setWhitelist(address user, bool status) external {
        require(msg.sender == governance, "Not governance");
        whitelisted[user] = status;
    }

    function emergencyWithdraw() external {
        require(msg.sender == governance, "Not governance");
        (bool ok, ) = governance.call{value: address(this).balance}("");
        require(ok, "Failed");
    }
}
