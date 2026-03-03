// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title GovernanceAttack — Stage 2 multi-contract governance system task.
/// @dev Token + Governor + Treasury. Vulnerable to flash-loan governance attack.
/// @notice VULNERABILITY: No snapshot — votes counted from current balance,
///         allowing flash-loan-funded proposal execution in a single block.

/// ── Governance Token ────────────────────────────────────────────────────────
contract GovToken {
    string public name = "GovToken";
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

/// ── Treasury ────────────────────────────────────────────────────────────────
contract Treasury {
    address public governor;
    GovToken public token;

    modifier onlyGovernor() {
        require(msg.sender == governor, "Not governor");
        _;
    }

    constructor(address _token) {
        token = GovToken(_token);
        governor = msg.sender; // Will be transferred to Governor contract
    }

    function setGovernor(address _governor) external {
        require(msg.sender == governor, "Not governor");
        governor = _governor;
    }

    /// @notice Execute arbitrary calls (approved by governance vote).
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyGovernor returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "Execution failed");
        return ret;
    }

    /// @notice Withdraw ETH from treasury (governance approved).
    function withdrawETH(address to, uint256 amount) external onlyGovernor {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "ETH transfer failed");
    }

    /// @notice Withdraw tokens from treasury (governance approved).
    function withdrawToken(address to, uint256 amount) external onlyGovernor {
        token.transfer(to, amount);
    }

    receive() external payable {}
}

/// ── Governor ────────────────────────────────────────────────────────────────
/// @dev Simplified on-chain governance with proposal + vote + execute.
///      VULNERABILITY: No snapshot mechanism — voting power from current
///      balance allows flash-loan governance takeover.
contract Governor {
    enum ProposalState {
        Pending,
        Active,
        Succeeded,
        Executed,
        Defeated
    }

    struct Proposal {
        uint256 id;
        address proposer;
        address target;
        uint256 value;
        bytes data;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 startBlock;
        uint256 endBlock;
        bool executed;
        mapping(address => bool) hasVoted;
    }

    GovToken public token;
    Treasury public treasury;

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;

    /// @dev VULNERABILITY: Quorum is only 10% of total supply.
    uint256 public quorumPercent = 10;
    /// @dev VULNERABILITY: Voting period is only 1 block.
    uint256 public votingPeriod = 1;
    uint256 public proposalThreshold = 0; // Anyone can propose

    event ProposalCreated(uint256 indexed id, address proposer);
    event Voted(
        uint256 indexed id,
        address voter,
        bool support,
        uint256 weight
    );
    event ProposalExecuted(uint256 indexed id);

    constructor(address _token, address _treasury) {
        token = GovToken(_token);
        treasury = Treasury(payable(_treasury));
    }

    function propose(
        address target,
        uint256 value,
        bytes calldata data
    ) external returns (uint256) {
        require(
            token.balanceOf(msg.sender) >= proposalThreshold,
            "Below threshold"
        );

        uint256 id = proposalCount++;
        Proposal storage p = proposals[id];
        p.id = id;
        p.proposer = msg.sender;
        p.target = target;
        p.value = value;
        p.data = data;
        p.startBlock = block.number;
        p.endBlock = block.number + votingPeriod;

        emit ProposalCreated(id, msg.sender);
        return id;
    }

    /// @dev VULNERABILITY: Uses token.balanceOf() directly — no snapshots.
    ///      Attacker borrows tokens via flash loan, votes, then returns them.
    function vote(uint256 proposalId, bool support) external {
        Proposal storage p = proposals[proposalId];
        require(block.number <= p.endBlock, "Voting ended");
        require(!p.hasVoted[msg.sender], "Already voted");

        // Voting power = current balance (no snapshot!)
        uint256 weight = token.balanceOf(msg.sender);
        require(weight > 0, "No voting power");

        p.hasVoted[msg.sender] = true;
        if (support) {
            p.forVotes += weight;
        } else {
            p.againstVotes += weight;
        }

        emit Voted(proposalId, msg.sender, support, weight);
    }

    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(block.number > p.endBlock, "Voting not ended");
        require(!p.executed, "Already executed");

        uint256 quorum = (token.totalSupply() * quorumPercent) / 100;
        require(p.forVotes >= quorum, "Quorum not reached");
        require(p.forVotes > p.againstVotes, "Proposal defeated");

        p.executed = true;
        treasury.execute(p.target, p.value, p.data);

        emit ProposalExecuted(proposalId);
    }

    function getProposalState(
        uint256 id
    ) external view returns (ProposalState) {
        Proposal storage p = proposals[id];
        if (p.executed) return ProposalState.Executed;
        if (block.number <= p.endBlock) return ProposalState.Active;
        uint256 quorum = (token.totalSupply() * quorumPercent) / 100;
        if (p.forVotes >= quorum && p.forVotes > p.againstVotes) {
            return ProposalState.Succeeded;
        }
        return ProposalState.Defeated;
    }
}
