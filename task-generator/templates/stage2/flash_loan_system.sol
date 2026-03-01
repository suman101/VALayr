// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title MockFlashLoanSystem — Stage 2 multi-contract flash loan task.
/// @dev Simulated AMM + Lending protocol with flash loan facility.
/// @notice Mocked liquidity — no real mainnet fork simulation.

/// ── Mock ERC20 Token ────────────────────────────────────────────────────────
contract MockToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol, uint256 _supply) {
        name = _name;
        symbol = _symbol;
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

/// ── Mock AMM Pool ───────────────────────────────────────────────────────────
contract MockAMM {
    MockToken public tokenA;
    MockToken public tokenB;
    uint256 public reserveA;
    uint256 public reserveB;

    constructor(address _tokenA, address _tokenB) {
        tokenA = MockToken(_tokenA);
        tokenB = MockToken(_tokenB);
    }

    function addLiquidity(uint256 amountA, uint256 amountB) external {
        tokenA.transferFrom(msg.sender, address(this), amountA);
        tokenB.transferFrom(msg.sender, address(this), amountB);
        reserveA += amountA;
        reserveB += amountB;
    }

    /// @notice Swap tokenA for tokenB using constant product formula.
    function swapAForB(uint256 amountIn) external returns (uint256 amountOut) {
        uint256 k = reserveA * reserveB;
        tokenA.transferFrom(msg.sender, address(this), amountIn);
        reserveA += amountIn;
        uint256 newReserveB = k / reserveA;
        amountOut = reserveB - newReserveB;
        reserveB = newReserveB;
        tokenB.transfer(msg.sender, amountOut);
    }

    function swapBForA(uint256 amountIn) external returns (uint256 amountOut) {
        uint256 k = reserveA * reserveB;
        tokenB.transferFrom(msg.sender, address(this), amountIn);
        reserveB += amountIn;
        uint256 newReserveA = k / reserveB;
        amountOut = reserveA - newReserveA;
        reserveA = newReserveA;
        tokenA.transfer(msg.sender, amountOut);
    }

    /// @notice Get spot price of tokenA in terms of tokenB.
    /// @dev VULNERABILITY: Spot price is manipulable via large trades.
    function getSpotPrice() external view returns (uint256) {
        return (reserveB * 1e18) / reserveA;
    }
}

/// ── Mock Lending Protocol ───────────────────────────────────────────────────
contract MockLending {
    MockToken public collateralToken;
    MockToken public debtToken;
    MockAMM public oracle; // Using AMM as price oracle — VULNERABLE

    mapping(address => uint256) public collateralDeposits;
    mapping(address => uint256) public debts;

    uint256 public collateralRatio = 150; // 150% collateral required

    constructor(address _collateral, address _debt, address _oracle) {
        collateralToken = MockToken(_collateral);
        debtToken = MockToken(_debt);
        oracle = MockAMM(_oracle);
    }

    function depositCollateral(uint256 amount) external {
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateralDeposits[msg.sender] += amount;
    }

    /// @notice Borrow debt tokens against collateral.
    /// @dev VULNERABILITY: Uses AMM spot price as oracle — manipulable via flash loan.
    function borrow(uint256 amount) external {
        uint256 price = oracle.getSpotPrice(); // Manipulable!
        uint256 collateralValue = (collateralDeposits[msg.sender] * price) /
            1e18;
        uint256 maxBorrow = (collateralValue * 100) / collateralRatio;
        require(debts[msg.sender] + amount <= maxBorrow, "Undercollateralized");

        debts[msg.sender] += amount;
        debtToken.transfer(msg.sender, amount);
    }

    function repay(uint256 amount) external {
        debtToken.transferFrom(msg.sender, address(this), amount);
        debts[msg.sender] -= amount;
    }

    /// @notice Flash loan facility.
    function flashLoan(address token, uint256 amount) external {
        MockToken t = MockToken(token);
        uint256 balBefore = t.balanceOf(address(this));
        t.transfer(msg.sender, amount);

        // Callback
        (bool ok, ) = msg.sender.call(
            abi.encodeWithSignature(
                "onFlashLoan(address,uint256)",
                token,
                amount
            )
        );
        require(ok, "Callback failed");

        uint256 fee = amount / 1000; // 0.1% fee
        require(
            t.balanceOf(address(this)) >= balBefore + fee,
            "Not repaid with fee"
        );
    }
}
