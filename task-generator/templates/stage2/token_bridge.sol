// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title TokenBridge — Stage 2 multi-contract cross-chain bridge task.
/// @dev Bridge + WrappedToken + Relayer. Multiple vulnerabilities:
///      replay attacks, signature malleability, unchecked mint authority.
/// @notice Simplified bridge model — no actual cross-chain, just the
///         lock/mint pattern with intentional security flaws.

/// ── Wrapped Token (minted on destination side) ──────────────────────────────
contract WrappedToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public bridge;

    /// @dev VULNERABILITY: bridge address can be changed by current bridge.
    ///      If bridge is compromised, attacker redirects mint authority.
    function setBridge(address _bridge) external {
        require(msg.sender == bridge || bridge == address(0), "Not bridge");
        bridge = _bridge;
    }

    modifier onlyBridge() {
        require(msg.sender == bridge, "Not bridge");
        _;
    }

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
        bridge = msg.sender;
    }

    function mint(address to, uint256 amount) external onlyBridge {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    /// @dev VULNERABILITY: burn() has no access control beyond checking
    ///      balance — anyone can burn their own tokens, but the bridge
    ///      doesn't verify burns match pending redemptions.
    function burn(address from, uint256 amount) external {
        require(balanceOf[from] >= amount, "Insufficient");
        if (from != msg.sender) {
            require(allowance[from][msg.sender] >= amount, "Allowance");
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        totalSupply -= amount;
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
}

/// ── Bridge (lock side) ──────────────────────────────────────────────────────
/// @dev Users lock ETH here; relayer mints wrapped tokens on the other "side".
contract Bridge {
    WrappedToken public wrappedToken;
    address public relayer;
    address public owner;

    uint256 public nonce;
    mapping(bytes32 => bool) public processedDeposits;
    mapping(bytes32 => bool) public processedWithdrawals;

    event Deposited(
        address indexed user,
        uint256 amount,
        uint256 nonce,
        bytes32 depositId
    );
    event Withdrawn(address indexed user, uint256 amount, bytes32 withdrawalId);

    constructor(address _wrappedToken) {
        wrappedToken = WrappedToken(_wrappedToken);
        owner = msg.sender;
        relayer = msg.sender;
    }

    function setRelayer(address _relayer) external {
        require(msg.sender == owner, "Not owner");
        relayer = _relayer;
    }

    /// @notice Lock ETH and emit deposit event for relayer.
    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");
        uint256 currentNonce = nonce++;
        bytes32 depositId = keccak256(
            abi.encodePacked(msg.sender, msg.value, currentNonce)
        );
        processedDeposits[depositId] = true;

        emit Deposited(msg.sender, msg.value, currentNonce, depositId);
    }

    /// @notice Relayer calls to mint wrapped tokens (destination side simulation).
    /// @dev VULNERABILITY: No signature verification — relayer is trusted entirely.
    ///      Compromised relayer can mint arbitrary amounts.
    function mintWrapped(
        address to,
        uint256 amount,
        bytes32 depositId
    ) external {
        require(msg.sender == relayer, "Not relayer");
        /// @dev VULNERABILITY: processedDeposits check uses depositId parameter
        ///      directly — relayer can submit fake depositIds.
        wrappedToken.mint(to, amount);
    }

    /// @notice Process withdrawal: burn wrapped tokens, release ETH.
    /// @dev VULNERABILITY: Uses a withdrawal hash derived solely from
    ///      user-supplied parameters — no chain-specific nonce.
    function withdraw(uint256 amount, bytes32 withdrawalId) external {
        /// @dev VULNERABILITY: Replay protection uses only withdrawalId
        ///      which can be the same across different bridge deployments.
        require(!processedWithdrawals[withdrawalId], "Already processed");
        processedWithdrawals[withdrawalId] = true;

        wrappedToken.burn(msg.sender, amount);

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "ETH transfer failed");

        emit Withdrawn(msg.sender, amount, withdrawalId);
    }

    /// @dev VULNERABILITY: emergencyWithdraw has no timelock or multi-sig.
    function emergencyWithdraw() external {
        require(msg.sender == owner, "Not owner");
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "Transfer failed");
    }

    receive() external payable {}
}

/// ── Relayer ─────────────────────────────────────────────────────────────────
/// @dev Off-chain relayer simulation. Processes deposit events.
///      VULNERABILITY: No event verification — processes any call from owner.
contract Relayer {
    Bridge public bridge;
    address public operator;

    mapping(bytes32 => bool) public relayed;

    constructor(address _bridge) {
        bridge = Bridge(payable(_bridge));
        operator = msg.sender;
    }

    /// @dev VULNERABILITY: No deposit proof verification.
    ///      Operator can relay fake deposits to mint unlimited wrapped tokens.
    function relay(address to, uint256 amount, bytes32 depositId) external {
        require(msg.sender == operator, "Not operator");
        require(!relayed[depositId], "Already relayed");
        relayed[depositId] = true;

        bridge.mintWrapped(to, amount, depositId);
    }
}
