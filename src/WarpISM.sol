// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.20;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract WarpISM is EIP712 {

    constructor (string memory name_, string memory version_) EIP712(name_, version_) {
    }

    function verify(bytes calldata _metadata, bytes calldata _message)
        external
        view
        returns (bool) {
        return true;
    }

}
