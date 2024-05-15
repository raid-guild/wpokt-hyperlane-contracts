// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.20;

interface IWarpController {
    event Fulfillment(bytes32 indexed orderId, bytes message);
}
