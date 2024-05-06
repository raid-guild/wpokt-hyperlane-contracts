// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.0;

import {IMailbox} from "../lib/hyperlane-monorepo/solidity/contracts/interfaces/IMailbox.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

abstract contract WarpController is IMailbox {

    address private _mailbox;
    address private _token;

    constructor(address mailbox_, address token_) {
        _mailbox = mailbox_;
        _token = token_;
    }
}
