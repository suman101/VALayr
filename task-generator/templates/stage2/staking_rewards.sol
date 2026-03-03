// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title StakingRewards — Stage 2 multi-contract staking system task.
/// @dev StakingToken + RewardDistributor + StakingPool. Multiple vulnerabilities:
///      reward calculation rounding, first-depositor advantage, withdrawal timing exploit.

/// ── Staking Token ───────────────────────────────────────────────────────────
contract StakingToken {
    string public name = "StakeToken";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(uint256 _supply) {
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

/// ── Reward Distributor ──────────────────────────────────────────────────────
/// @dev Distributes reward tokens to the staking pool on a schedule.
///      VULNERABILITY: notifyReward() callable by anyone — attacker can
///      inject reward notifications backed by zero actual tokens.
contract RewardDistributor {
    StakingToken public rewardToken;
    address public stakingPool;
    address public owner;

    uint256 public rewardRate;
    uint256 public lastDistribution;
    uint256 public distributionPeriod = 7 days;

    constructor(address _rewardToken) {
        rewardToken = StakingToken(_rewardToken);
        owner = msg.sender;
    }

    function setStakingPool(address _pool) external {
        require(msg.sender == owner, "Not owner");
        stakingPool = _pool;
    }

    /// @notice Fund rewards and start distribution.
    function fundRewards(uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        rewardToken.transferFrom(msg.sender, address(this), amount);
        rewardRate = amount / distributionPeriod;
        lastDistribution = block.timestamp;
    }

    /// @notice Distribute pending rewards to staking pool.
    function distribute() external {
        require(stakingPool != address(0), "No pool");
        uint256 elapsed = block.timestamp - lastDistribution;
        uint256 amount = elapsed * rewardRate;

        uint256 balance = rewardToken.balanceOf(address(this));
        if (amount > balance) amount = balance;

        if (amount > 0) {
            rewardToken.transfer(stakingPool, amount);
            lastDistribution = block.timestamp;
        }
    }

    /// @dev VULNERABILITY: Anyone can call notifyReward() to set a fake reward rate
    ///      on the pool without actually transferring tokens.
    function notifyReward(uint256 amount) external {
        require(stakingPool != address(0), "No pool");
        // No access control! No token transfer verification!
        (bool ok, ) = stakingPool.call(
            abi.encodeWithSignature("notifyRewardAmount(uint256)", amount)
        );
        require(ok, "Notification failed");
    }
}

/// ── Staking Pool ────────────────────────────────────────────────────────────
/// @dev Users stake tokens to earn rewards. Based on Synthetix StakingRewards
///      but with intentional vulnerabilities.
contract StakingPool {
    StakingToken public stakingToken;
    StakingToken public rewardToken;
    address public distributor;

    uint256 public totalStaked;
    mapping(address => uint256) public stakedBalance;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;

    uint256 public rewardPerTokenStored;
    uint256 public rewardRate;
    uint256 public lastUpdateTime;
    uint256 public periodFinish;

    /// @dev VULNERABILITY: Duration is extremely short — rewards accrue fast.
    uint256 public rewardsDuration = 1 hours;

    constructor(address _stakingToken, address _rewardToken) {
        stakingToken = StakingToken(_stakingToken);
        rewardToken = StakingToken(_rewardToken);
        distributor = msg.sender;
    }

    function setDistributor(address _dist) external {
        require(msg.sender == distributor, "Not distributor");
        distributor = _dist;
    }

    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = lastTimeRewardApplicable();
        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }

    function lastTimeRewardApplicable() public view returns (uint256) {
        return block.timestamp < periodFinish ? block.timestamp : periodFinish;
    }

    /// @dev VULNERABILITY: When totalStaked == 0, rewardPerToken stays stale.
    ///      First depositor after a reward notification captures all rewards.
    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) {
            return rewardPerTokenStored;
        }
        return
            rewardPerTokenStored +
            ((lastTimeRewardApplicable() - lastUpdateTime) *
                rewardRate *
                1e18) /
            totalStaked;
    }

    function earned(address account) public view returns (uint256) {
        return
            (stakedBalance[account] *
                (rewardPerToken() - userRewardPerTokenPaid[account])) /
            1e18 +
            rewards[account];
    }

    function stake(uint256 amount) external updateReward(msg.sender) {
        require(amount > 0, "Cannot stake 0");
        stakingToken.transferFrom(msg.sender, address(this), amount);
        totalStaked += amount;
        stakedBalance[msg.sender] += amount;
    }

    /// @dev VULNERABILITY: No withdrawal cooldown — stake-claim-unstake
    ///      in same block captures full reward period.
    function withdraw(uint256 amount) external updateReward(msg.sender) {
        require(stakedBalance[msg.sender] >= amount, "Insufficient");
        totalStaked -= amount;
        stakedBalance[msg.sender] -= amount;
        stakingToken.transfer(msg.sender, amount);
    }

    function claimReward() external updateReward(msg.sender) {
        uint256 reward = rewards[msg.sender];
        if (reward > 0) {
            rewards[msg.sender] = 0;
            rewardToken.transfer(msg.sender, reward);
        }
    }

    /// @dev VULNERABILITY: No access control — anyone can call this.
    ///      Combined with RewardDistributor.notifyReward(), enables
    ///      fake reward injection.
    function notifyRewardAmount(
        uint256 reward
    ) external updateReward(address(0)) {
        if (block.timestamp >= periodFinish) {
            rewardRate = reward / rewardsDuration;
        } else {
            uint256 remaining = periodFinish - block.timestamp;
            uint256 leftover = remaining * rewardRate;
            rewardRate = (reward + leftover) / rewardsDuration;
        }

        lastUpdateTime = block.timestamp;
        periodFinish = block.timestamp + rewardsDuration;
    }
}
