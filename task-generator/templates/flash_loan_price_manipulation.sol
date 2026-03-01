// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title FlashLoanPriceManipulation — Flash loan oracle manipulation.
/// @dev Vulnerable: uses spot price from AMM pool as oracle, manipulable via flash loan.
contract FlashLoanPriceManipulation {
    // Simulated AMM pool state
    uint256 public reserveToken;
    uint256 public reserveETH;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    address public owner;

    constructor() payable {
        owner = msg.sender;
        // Initial pool: 1000 tokens, 10 ETH
        reserveToken = 1000e18;
        reserveETH = 10 ether;
    }

    /// @notice Simulated AMM swap: ETH → Token
    function swapETHForToken() external payable returns (uint256 tokensOut) {
        require(msg.value > 0, "No ETH");
        // x * y = k
        uint256 k = reserveToken * reserveETH;
        reserveETH += msg.value;
        uint256 newReserveToken = k / reserveETH;
        tokensOut = reserveToken - newReserveToken;
        reserveToken = newReserveToken;
    }

    /// @notice Simulated AMM swap: Token → ETH
    function swapTokenForETH(
        uint256 tokenAmount
    ) external returns (uint256 ethOut) {
        uint256 k = reserveToken * reserveETH;
        reserveToken += tokenAmount;
        uint256 newReserveETH = k / reserveToken;
        ethOut = reserveETH - newReserveETH;
        reserveETH = newReserveETH;
        (bool ok, ) = msg.sender.call{value: ethOut}("");
        require(ok, "Failed");
    }

    /// @notice Get "price" of token in ETH — VULNERABLE ORACLE
    /// @dev VULNERABILITY: Spot price from pool, manipulable via large trades.
    function getTokenPrice() public view returns (uint256) {
        return (reserveETH * 1e18) / reserveToken;
    }

    /// @notice Deposit collateral (tokens) and borrow ETH at oracle price
    function depositAndBorrow(uint256 tokenAmount) external {
        collateral[msg.sender] += tokenAmount;
        // Borrow up to 80% of collateral value at current "price"
        uint256 collateralValueETH = (tokenAmount * getTokenPrice()) / 1e18;
        uint256 borrowable = (collateralValueETH * 80) / 100;
        debt[msg.sender] += borrowable;
        (bool ok, ) = msg.sender.call{value: borrowable}("");
        require(ok, "Failed");
    }

    /// @notice Flash loan facility (for testing)
    function flashLoan(uint256 amount) external {
        uint256 balBefore = address(this).balance;
        (bool ok, ) = msg.sender.call{value: amount}(
            abi.encodeWithSignature("onFlashLoan(uint256)", amount)
        );
        require(ok, "Callback failed");
        require(address(this).balance >= balBefore, "Not repaid");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
