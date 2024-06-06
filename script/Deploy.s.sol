// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";

import {console2} from "forge-std/console2.sol";

import {PausableIsm} from "src/hyperlane/PausableIsm.sol";
import {Mailbox} from "src/hyperlane/Mailbox.sol";
import {WarpISM} from "src/WarpISM.sol";
import {OmniToken} from "src/OmniToken.sol";
import {wPOKTMintController} from "src/wPOKTMintController.sol";

contract DeployScript is Script {
    constructor() {}

    address internal _deployer;
    address internal _owner;
    PausableIsm internal _defaultIsm;
    Mailbox internal _mailbox;
    WarpISM internal _warpISM;
    OmniToken internal _token;
    wPOKTMintController internal _mintController;
    uint32 internal _chainId;
    uint256 internal _nonce;

    uint256 internal constant _mintLimit = 10 ** 18;
    uint256 internal constant _mintPerSecond = 10 ** 16;


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

        address _predictedDefaultIsm = vm.computeCreateAddress(_deployer, _nonce++);
        console2.log("Deploying PausableIsm at: ", _predictedDefaultIsm);
        _defaultIsm = new PausableIsm(_owner);
        console2.log("Deployed PausableIsm at: ", address(_defaultIsm));
        assert(address(_defaultIsm) == _predictedDefaultIsm);

        address _predictedMailbox = vm.computeCreateAddress(_deployer, _nonce++);
        console2.log("Deploying Mailbox at: ", _predictedMailbox);
        _mailbox = new Mailbox(_chainId);
        _mailbox.initialize(_owner, address(_defaultIsm));
        console2.log("Deployed Mailbox at: ", address(_mailbox));
        assert(address(_mailbox) == _predictedMailbox);

        _nonce+=1;

        address _preditectWarpISM = vm.computeCreateAddress(_deployer, _nonce++);
        console2.log("Deploying WarpISM at: ", _preditectWarpISM);
        _warpISM = new WarpISM("WarpISM", "1", _owner);
        console2.log("Deployed WarpISM at: ", address(_warpISM));
        assert(address(_warpISM) == _preditectWarpISM);

        address _predictedToken = vm.computeCreateAddress(_deployer, _nonce++);
        address _predictedMintController = vm.computeCreateAddress(_deployer, _nonce++);

        console2.log("Deploying Token at: ", _predictedToken);
        _token = new OmniToken(_owner, address(_predictedMintController), _owner, "Wrapped POKT", "wPOKT");
        console2.log("Deployed Token at: ", address(_token));
        assert(address(_token) == _predictedToken);

        console2.log("Deploying MintController at: ", _predictedMintController);
        _mintController = new wPOKTMintController(address(_mailbox), address(_token), address(_warpISM), _owner, _mintLimit, _mintPerSecond);
        console2.log("Deployed MintController at: ", address(_mintController));
        assert(address(_mintController) == _predictedMintController);


        vm.stopBroadcast();
    }
}
