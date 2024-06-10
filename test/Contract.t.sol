// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {CREATE3Factory} from "@create3/CREATE3Factory.sol";
import {wPOKTMintController} from "@src/wPOKTMintController.sol";
import {Mailbox} from "@hyperlane/Mailbox.sol";
import {OmniToken} from "@src/OmniToken.sol";

contract ContractTest is Test {

    wPOKTMintController public mintController;
    Mailbox public mailbox;
    OmniToken public token;

    function setUp() public {
        uint256 chainId = block.chainid;
        mailbox = new Mailbox(uint32(chainId));
    }

    function testExample() public {
        vm.startPrank(address(0xB0B));
        console2.log("Hello world!");
        assertTrue(true);
    }
}
