// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ERC20ApproveRace — ERC-20 approve/transferFrom race condition.
/// @dev Vulnerable: approve() does not reset-to-zero first, enabling a
///      front-running attack where the spender can spend both the old and
///      new allowance within the same block.
contract ERC20ApproveRace {
    string public constant name = "VulnToken";
    string public constant symbol = "VULN";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor() {
        // Mint initial supply to deployer
        uint256 initial = 1_000_000e18;
        balanceOf[msg.sender] = initial;
        totalSupply = initial;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    /// @dev VULNERABILITY: Directly overwrites allowance without requiring
    ///      reset to zero first. A spender watching the mempool can
    ///      transferFrom the old allowance, then the new one is set.
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(
            allowance[from][msg.sender] >= amount,
            "Insufficient allowance"
        );
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
