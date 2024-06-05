// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.13;

import {CREATE3Script} from "./base/CREATE3Script.sol";

import {console2} from "forge-std/console2.sol";

import {PausableIsm} from "src/hyperlane/PausableIsm.sol";

contract DeployScript is CREATE3Script {
    constructor() CREATE3Script(vm.envString("VERSION")) {}

    address internal _deployer;

    function deployPausableIsm() external {
        uint256 deployerPrivateKey = uint256(vm.envBytes32("PRIVATE_KEY"));
        _deployer = vm.addr(deployerPrivateKey);

        console2.log("Deploying PausableIsm...");
        console2.log("Deployer: ", _deployer);

        vm.startBroadcast(deployerPrivateKey);

        /* Example CREATE3 deployment
        uint256 param = 123;
        c = Contract(
            create3.deploy(
                getCreate3ContractSalt("Contract"), bytes.concat(type(Contract).creationCode, abi.encode(param))
            )
        ); 
        */

        bytes32 salt = getCreate3ContractSalt("PausableIsm");

        address predeterminedISM = getCreate3Contract("PausableIsm");

        console2.log("PredeterminedISM: ", predeterminedISM);

        bytes memory creationCode = bytes.concat(type(PausableIsm).creationCode, abi.encode(_deployer));

        address ism = create3.deploy(salt, creationCode);

        console2.log("ISM: ", ism);

        vm.stopBroadcast();
    }
}
