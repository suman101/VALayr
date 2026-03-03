// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title CrossContractReentrancy — Stage 2 multi-contract reentrancy task.
/// @dev Reentrancy between a Vault and a yield-bearing TokenWrapper.
/// @notice VULNERABILITY: withdraw() in Vault calls TokenWrapper which calls
///         back into Vault before balance update completes.

/// ── Mock ERC20 ──────────────────────────────────────────────────────────────
contract SimpleToken {
    string public name;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, uint256 _supply) {
        name = _name;
        totalSupply = _supply;
        balanceOf[msg.sender] = _supply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "Allowance");
        require(balanceOf[from] >= amount, "Insufficient");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}

/// ── Token Wrapper (yield wrapper) ───────────────────────────────────────────
/// @dev Wraps SimpleToken into yield-bearing shares. On unwrap, calls the
///      Vault's `notifyRedemption()` hook — cross-contract callback.
contract TokenWrapper {
    SimpleToken public underlying;
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    address public vault;

    constructor(address _underlying) {
        underlying = SimpleToken(_underlying);
    }

    function setVault(address _vault) external {
        require(vault == address(0), "Already set");
        vault = _vault;
    }

    function wrap(uint256 amount) external {
        underlying.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += amount;
        totalShares += amount;
    }

    /// @dev VULNERABILITY: Calls external vault.notifyRedemption() before
    ///      updating shares. If vault re-enters unwrap, shares are double-spent.
    function unwrap(uint256 amount) external {
        require(shares[msg.sender] >= amount, "Insufficient shares");

        // External call BEFORE state update — reentrancy vector
        if (vault != address(0)) {
            (bool ok, ) = vault.call(
                abi.encodeWithSignature(
                    "notifyRedemption(address,uint256)",
                    msg.sender,
                    amount
                )
            );
            require(ok, "Vault notification failed");
        }

        // State update AFTER external call
        shares[msg.sender] -= amount;
        totalShares -= amount;
        underlying.transfer(msg.sender, amount);
    }

    function getShareValue() external view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (underlying.balanceOf(address(this)) * 1e18) / totalShares;
    }
}

/// ── Vault ───────────────────────────────────────────────────────────────────
/// @dev Holds wrapped tokens. Users deposit to earn yield.
///      VULNERABILITY: notifyRedemption() callback from TokenWrapper allows
///      re-entry into withdraw(), draining vault funds.
contract Vault {
    TokenWrapper public wrapper;
    SimpleToken public token;

    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;

    constructor(address _wrapper, address _token) {
        wrapper = TokenWrapper(_wrapper);
        token = SimpleToken(_token);
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        token.approve(address(wrapper), amount);
        wrapper.wrap(amount);
        deposits[msg.sender] += amount;
        totalDeposits += amount;
    }

    /// @dev VULNERABILITY: Calls wrapper.unwrap() which triggers
    ///      notifyRedemption() callback before deposits are updated.
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient");

        // Unwrap triggers callback via notifyRedemption
        wrapper.unwrap(amount);

        // State update happens AFTER the external callback chain
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
    }

    /// @notice Called by TokenWrapper during unwrap — re-entry point.
    /// @dev No reentrancy guard on this callback.
    function notifyRedemption(address user, uint256 amount) external {
        require(msg.sender == address(wrapper), "Only wrapper");
        // Bookkeeping — but attacker can exploit the fact that
        // deposits[user] hasn't been decremented yet.
    }

    function getVaultBalance() external view returns (uint256) {
        return wrapper.shares(address(this));
    }
}
