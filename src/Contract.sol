// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.0;

import {IMessageRecipient} from "@hyperlane/interfaces/IMessageRecipient.sol";
import {IInterchainSecurityModule} from "@hyperlane/interfaces/IInterchainSecurityModule.sol";

abstract contract WarpController is IMessageRecipient, IInterchainSecurityModule {
    uint256 public immutable param;

    constructor(uint256 param_) {
        param = param_;
    }
}
