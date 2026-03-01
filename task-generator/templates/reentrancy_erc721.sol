// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ReentrancyERC721 — ERC721 callback reentrancy.
/// @dev Vulnerable: onERC721Received callback allows re-entry into mint.
contract ReentrancyERC721 {
    mapping(uint256 => address) public owners;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 public maxSupply = 10;
    uint256 public price = 0.1 ether;

    function mint(uint256 count) external payable {
        require(msg.value >= count * price, "Underpaid");
        require(totalSupply + count <= maxSupply, "Max supply");

        for (uint256 i = 0; i < count; i++) {
            uint256 tokenId = totalSupply;
            // BUG: totalSupply updated inside loop AFTER external call
            owners[tokenId] = msg.sender;
            balanceOf[msg.sender]++;

            // Simulate safeTransferFrom callback
            if (_isContract(msg.sender)) {
                (bool ok, ) = msg.sender.call(
                    abi.encodeWithSignature(
                        "onERC721Received(address,address,uint256,bytes)",
                        address(this),
                        msg.sender,
                        tokenId,
                        ""
                    )
                );
                require(ok, "Callback failed");
            }

            totalSupply++;
        }
    }

    function _isContract(address a) internal view returns (bool) {
        return a.code.length > 0;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
