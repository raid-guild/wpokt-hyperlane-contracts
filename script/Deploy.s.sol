// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";

import {console2} from "forge-std/console2.sol";

import {PausableIsm} from "src/hyperlane/PausableIsm.sol";
import {Mailbox} from "src/hyperlane/Mailbox.sol";

contract DeployScript is Script {
    constructor() {}

    address internal _deployer;
    PausableIsm internal _ism;
    Mailbox internal _mailbox;
    uint32 internal _chainId;
    bytes32 internal constant _salt = bytes32(keccak256(abi.encode("WPOKT")));

    function run() external {
        uint256 deployerPrivateKey = uint256(vm.envBytes32("PRIVATE_KEY"));
        _deployer = vm.addr(deployerPrivateKey);
        _chainId = uint32(block.chainid);

        console2.log("Deployer: ", _deployer);
        console2.log("Chain ID: ", _chainId);

        vm.startBroadcast(deployerPrivateKey);

        console2.log("Deploying PausableIsm...");
        _ism = new PausableIsm{salt: _salt}(_deployer);
        console2.log("Deployed PausableIsm at: ", address(_ism));

        console2.log("Deploying Mailbox...");
        _mailbox = new Mailbox{salt: _salt}(_chainId);
        _mailbox.initialize(_deployer, address(_ism));
        console2.log("Deployed Mailbox at: ", address(_mailbox));

        vm.stopBroadcast();
    }
}
