// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.20;

interface IWarpController {
    error SenderMustBeCaller();

    event Fulfillment(bytes32 indexed orderId, bytes message);
    event WarpMint(address indexed recipient, uint256 amount, address indexed sender);
}
