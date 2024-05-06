// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.20;

import {ILimiter} from "@interfaces/ILimiter.sol";

abstract contract Limiter is ILimiter {
    uint256 private _currentMintLimit = 335_000 ether;
    uint256 public lastMint;
    uint256 public maxMintLimit = 335_000 ether;
    uint256 public mintPerSecond = 3.8773 ether;

    /// @notice Sets the mint limit and mint per second cooldown rate.
    /// @dev Can only be called by admin.
    /// Emits a MintCooldownSet event upon successful setting.
    /// @param newLimit The new mint limit to set.
    /// @param newMintPerSecond The new mint per second cooldown rate to set.
    function _setMintCooldown(uint256 newLimit, uint256 newMintPerSecond) internal virtual {
        if (newLimit < mintPerSecond) {
            revert InvalidCooldownConfig();
        }
        maxMintLimit = newLimit;
        mintPerSecond = newMintPerSecond;

        emit MintCooldownSet(newLimit, newMintPerSecond);
    }

    /// @dev Updates the mint limit based on the cooldown mechanism.
    /// @param _amount The amount of tokens to mint.
    /// @return The updated mint limit.
    function _enforceMintLimit(uint256 _amount) internal returns (uint256) {
        uint256 timePassed = block.timestamp - lastMint;
        uint256 mintableFromCooldown = timePassed * mintPerSecond;
        uint256 previousMintLimit = _currentMintLimit;
        uint256 maxMintable = maxMintLimit;

        // We enforce that amount is not greater than the maximum mint or the current allowed by cooldown
        if (_amount > mintableFromCooldown + previousMintLimit || _amount > maxMintable) {
            revert OverMintLimit();
        }

        // If the cooldown has fully recovered; we are allowed to mint up to the maximum amount
        if (previousMintLimit + mintableFromCooldown >= maxMintable) {
            _currentMintLimit = maxMintable - _amount;
            lastMint = block.timestamp;
            return maxMintable - _amount;

            // Otherwise the cooldown has not fully recovered; we are allowed to mint up to the recovered amount
        } else {
            uint256 mintable = previousMintLimit + mintableFromCooldown;
            _currentMintLimit = mintable - _amount;
            lastMint = block.timestamp;
            return mintable - _amount;
        }
    }

    /*//////////////////////////////////////////////////////////////
    // View Functions
    //////////////////////////////////////////////////////////////*/

    function currentMintLimit() external view returns (uint256) {
        uint256 mintableFromCooldown = (block.timestamp - lastMint) * mintPerSecond;
        if (mintableFromCooldown + _currentMintLimit > maxMintLimit) {
            return maxMintLimit;
        } else {
            return mintableFromCooldown + _currentMintLimit;
        }
    }

    function lastMintLimit() external view returns (uint256) {
        return _currentMintLimit;
    }
}
