// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.20;

interface ILimiter {
    error OverMintLimit();
    error InvalidCooldownConfig();

    event MintCooldownSet(uint256 newLimit, uint256 newCooldown);
    event CurrentMintLimit(uint256 indexed limit, uint256 indexed lastMint);
}
