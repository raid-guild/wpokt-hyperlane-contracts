// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";

import {console2} from "forge-std/console2.sol";

import {PausableIsm} from "src/hyperlane/PausableIsm.sol";
import {Mailbox} from "src/hyperlane/Mailbox.sol";

contract DeployScript is Script {
    constructor() {}

    address internal _deployer;
    address internal _owner;
    PausableIsm internal _ism;
    Mailbox internal _mailbox;
    uint32 internal _chainId;
    uint256 internal _nonce;

    function run() external {
        uint256 deployerPrivateKey = uint256(vm.envBytes32("PRIVATE_KEY"));
        _deployer = vm.addr(deployerPrivateKey);
        _chainId = uint32(block.chainid);
        _owner = _deployer;
        _nonce = vm.getNonce(_deployer);

        console2.log("Deployer: ", _deployer);
        console2.log("Chain ID: ", _chainId);
        console2.log("Owner: ", _owner);

        vm.startBroadcast(deployerPrivateKey);

        console2.log("Deploying PausableIsm...");
        address _predicted = vm.computeCreateAddress(_deployer, ++_nonce);
        _ism = new PausableIsm(_owner);
        console2.log("Deployed PausableIsm at: ", address(_ism));
        assert(address(_ism) == _predicted, "PausableIsm address mismatch");

        console2.log("Deploying Mailbox...");
        _mailbox = new Mailbox(_chainId);
        _mailbox.initialize(_owner, address(_ism));
        console2.log("Deployed Mailbox at: ", address(_mailbox));

        vm.stopBroadcast();
    }
}
