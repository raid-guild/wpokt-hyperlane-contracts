// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.20;

interface IOmniWarpController {
    event Fulfillment(bytes32 indexed orderId, bytes message);
}
