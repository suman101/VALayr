// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title OracleManipulation — Stage 2 multi-contract oracle task.
/// @dev Price oracle + Leveraged trading protocol. Vulnerable to oracle manipulation
///      via direct reserve modification and stale price exploitation.
/// @notice VULNERABILITY: TWAP window is only 1 block, allowing same-block manipulation.

/// ── Mock ERC20 ──────────────────────────────────────────────────────────────
contract OracleToken {
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

/// ── Price Oracle ────────────────────────────────────────────────────────────
/// @dev Simple TWAP oracle backed by a liquidity pool.
///      VULNERABILITY: Only stores 1-block TWAP — trivially manipulable.
contract PriceOracle {
    OracleToken public tokenA;
    OracleToken public tokenB;

    uint256 public reserveA;
    uint256 public reserveB;

    uint256 public price0CumulativeLast;
    uint256 public price1CumulativeLast;
    uint32 public blockTimestampLast;

    /// @dev VULNERABILITY: TWAP window of 1 block — no protection.
    uint32 public constant TWAP_WINDOW = 1;

    constructor(address _tokenA, address _tokenB) {
        tokenA = OracleToken(_tokenA);
        tokenB = OracleToken(_tokenB);
        blockTimestampLast = uint32(block.timestamp);
    }

    function addLiquidity(uint256 amountA, uint256 amountB) external {
        tokenA.transferFrom(msg.sender, address(this), amountA);
        tokenB.transferFrom(msg.sender, address(this), amountB);
        _update(reserveA + amountA, reserveB + amountB);
    }

    function swap(
        bool aToB,
        uint256 amountIn
    ) external returns (uint256 amountOut) {
        if (aToB) {
            tokenA.transferFrom(msg.sender, address(this), amountIn);
            uint256 k = reserveA * reserveB;
            uint256 newReserveA = reserveA + amountIn;
            uint256 newReserveB = k / newReserveA;
            amountOut = reserveB - newReserveB;
            tokenB.transfer(msg.sender, amountOut);
            _update(newReserveA, newReserveB);
        } else {
            tokenB.transferFrom(msg.sender, address(this), amountIn);
            uint256 k = reserveA * reserveB;
            uint256 newReserveB = reserveB + amountIn;
            uint256 newReserveA = k / newReserveB;
            amountOut = reserveA - newReserveA;
            tokenA.transfer(msg.sender, amountOut);
            _update(newReserveA, newReserveB);
        }
    }

    /// @dev VULNERABILITY: getPrice() uses current spot price, not TWAP.
    ///      The cumulative accumulators exist but are never actually used
    ///      to compute a time-weighted average.
    function getPrice() external view returns (uint256) {
        require(reserveA > 0, "No liquidity");
        return (reserveB * 1e18) / reserveA;
    }

    function _update(uint256 _reserveA, uint256 _reserveB) internal {
        uint32 timeElapsed = uint32(block.timestamp) - blockTimestampLast;
        if (timeElapsed > 0 && reserveA > 0 && reserveB > 0) {
            price0CumulativeLast +=
                ((reserveB * 1e18) / reserveA) *
                timeElapsed;
            price1CumulativeLast +=
                ((reserveA * 1e18) / reserveB) *
                timeElapsed;
        }
        reserveA = _reserveA;
        reserveB = _reserveB;
        blockTimestampLast = uint32(block.timestamp);
    }
}

/// ── Leveraged Trading Protocol ──────────────────────────────────────────────
/// @dev Allows leveraged long/short positions using the oracle price.
///      VULNERABILITY: Uses manipulated oracle price for position valuation,
///      allowing attacker to open leveraged positions at fake prices.
contract LeveragedTrading {
    struct Position {
        address trader;
        bool isLong;
        uint256 collateral;
        uint256 size;
        uint256 entryPrice;
        bool open;
    }

    PriceOracle public oracle;
    OracleToken public collateralToken;

    uint256 public positionCount;
    mapping(uint256 => Position) public positions;
    uint256 public totalCollateral;

    /// @dev Max leverage 10x
    uint256 public constant MAX_LEVERAGE = 10;
    /// @dev Liquidation threshold 80%
    uint256 public constant LIQUIDATION_THRESHOLD = 80;

    constructor(address _oracle, address _collateralToken) {
        oracle = PriceOracle(_oracle);
        collateralToken = OracleToken(_collateralToken);
    }

    /// @dev VULNERABILITY: Entry price comes from manipulable oracle.
    function openPosition(
        uint256 collateral,
        uint256 leverage,
        bool isLong
    ) external returns (uint256) {
        require(leverage > 0 && leverage <= MAX_LEVERAGE, "Invalid leverage");

        collateralToken.transferFrom(msg.sender, address(this), collateral);

        uint256 price = oracle.getPrice(); // Manipulable!
        uint256 size = collateral * leverage;

        uint256 id = positionCount++;
        positions[id] = Position({
            trader: msg.sender,
            isLong: isLong,
            collateral: collateral,
            size: size,
            entryPrice: price,
            open: true
        });
        totalCollateral += collateral;

        return id;
    }

    /// @dev VULNERABILITY: Close price also from oracle — profit/loss at fake price.
    function closePosition(uint256 positionId) external {
        Position storage p = positions[positionId];
        require(p.trader == msg.sender, "Not owner");
        require(p.open, "Already closed");

        uint256 currentPrice = oracle.getPrice(); // Manipulable!
        int256 pnl;

        if (p.isLong) {
            pnl =
                (int256(p.size) *
                    (int256(currentPrice) - int256(p.entryPrice))) /
                int256(p.entryPrice);
        } else {
            pnl =
                (int256(p.size) *
                    (int256(p.entryPrice) - int256(currentPrice))) /
                int256(p.entryPrice);
        }

        uint256 payout;
        if (pnl >= 0) {
            payout = p.collateral + uint256(pnl);
            // Cap at available balance
            uint256 available = collateralToken.balanceOf(address(this));
            if (payout > available) payout = available;
        } else {
            uint256 loss = uint256(-pnl);
            payout = loss >= p.collateral ? 0 : p.collateral - loss;
        }

        p.open = false;
        totalCollateral -= p.collateral;

        if (payout > 0) {
            collateralToken.transfer(msg.sender, payout);
        }
    }

    /// @dev Liquidate underwater position — also uses manipulable oracle.
    function liquidate(uint256 positionId) external {
        Position storage p = positions[positionId];
        require(p.open, "Not open");

        uint256 currentPrice = oracle.getPrice();
        int256 pnl;

        if (p.isLong) {
            pnl =
                (int256(p.size) *
                    (int256(currentPrice) - int256(p.entryPrice))) /
                int256(p.entryPrice);
        } else {
            pnl =
                (int256(p.size) *
                    (int256(p.entryPrice) - int256(currentPrice))) /
                int256(p.entryPrice);
        }

        uint256 remainingCollateral;
        if (pnl >= 0) {
            remainingCollateral = p.collateral + uint256(pnl);
        } else {
            uint256 loss = uint256(-pnl);
            remainingCollateral = loss >= p.collateral
                ? 0
                : p.collateral - loss;
        }

        uint256 threshold = (p.collateral * LIQUIDATION_THRESHOLD) / 100;
        require(remainingCollateral < threshold, "Not liquidatable");

        p.open = false;
        totalCollateral -= p.collateral;

        // Liquidator gets 5% of remaining collateral
        uint256 reward = remainingCollateral / 20;
        if (reward > 0) {
            collateralToken.transfer(msg.sender, reward);
        }
    }
}
