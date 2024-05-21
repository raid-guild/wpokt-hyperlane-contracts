// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.20;

import {WarpMintController} from "@src/WarpMintController.sol";
import {Limiter} from "@src/Limiter.sol";

contract wPOKTMintController is WarpMintController, Limiter {
    constructor(
        address mailbox_,
        address token_,
        address ism_,
        address defaultAdmin,
        uint256 newLimit_,
        uint256 newMintPerSecond_
    ) WarpMintController(mailbox_, token_, ism_, defaultAdmin) {
        _setMintCooldown(newLimit_, newMintPerSecond_);
    }
}
