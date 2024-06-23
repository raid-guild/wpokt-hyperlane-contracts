// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { CallUtils } from "./CallUtils.sol";

contract Account {
    uint256 public state;
    address public owner;

    event Executed();

    error NotOwner();
    error InvalidOperation();
    error ExecutionFailed();

    constructor(address _owner) {
        owner = _owner;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    function execute(address to, uint256 value, bytes calldata data, uint256 operation)
        external
        payable
        returns (bytes memory result)
    {
        if (msg.sender != owner) {
            revert NotOwner();
        }

        ++state;

        bool success;

        if (operation == 0) {
            // solhint-disable-next-line avoid-low-level-calls
            (success, result) = to.call{value: value}(data);
        } else if (operation == 1) {
            // solhint-disable-next-line avoid-low-level-calls
            (success, result) = to.delegatecall(data);
        } else {
            revert InvalidOperation();
        }

        if (!success) {
            CallUtils.revertFromReturnedData(result);
        }

        emit Executed();
    }
}

contract AccountFactory {
    mapping(address => address) public accounts;

    event AccountCreated(address account);

    function getAccount() external returns (address account) {
        account = accounts[msg.sender];
        if (account == address(0)) {
            account = address(new Account(msg.sender));
            accounts[msg.sender] = account;
            emit AccountCreated(account);
        }
    }
}
