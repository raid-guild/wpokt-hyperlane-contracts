// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";

import {console2} from "forge-std/console2.sol";

import {PausableIsm} from "src/hyperlane/PausableIsm.sol";
import {Mailbox} from "@hyperlane/Mailbox.sol";
import {WarpISM} from "src/WarpISM.sol";
import {OmniToken} from "src/OmniToken.sol";
import {wPOKTMintController} from "src/wPOKTMintController.sol";
import {AccountFactory} from "src/Account.sol";
import {Multicall3} from "src/Multicall3.sol";
import {TestPostDispatchHook} from "@hyperlane/test/TestPostDispatchHook.sol";

contract LocalDeployScript is Script {
    constructor() {}

    address internal _deployer;
    address internal _owner;
    PausableIsm internal _defaultIsm;
    Mailbox internal _mailbox;
    WarpISM internal _warpISM;
    OmniToken internal _token;
    wPOKTMintController internal _mintController;
    AccountFactory internal _accountFactory;
    Multicall3 internal _multicall3;
    uint32 internal _chainId;
    TestPostDispatchHook internal _defaultHook;

    uint256 internal constant _mintLimit = 10 ** 18;
    uint256 internal constant _mintPerSecond = 10 ** 16;

    bytes32 internal constant _SALT = keccak256("POKT");

    struct NetworkConfig {
        address[] validators;
        uint256 signerThreshold;
    }

    NetworkConfig internal _config;

    function getAnvilEthConfig() internal pure returns (NetworkConfig memory anvilNetworkConfig) {
        address[] memory validators = new address[](3);
        validators[0] = address(0x0E90A32Df6f6143F1A91c25d9552dCbc789C34Eb);
        validators[1] = address(0x958d1F55E14Cba24a077b9634F16f83565fc9411);
        validators[2] = address(0x4c672Edd2ec8eac8f0F1709f33de9A2E786e6912);

        anvilNetworkConfig = NetworkConfig({validators: validators, signerThreshold: 2});
    }

    function run() external {
        _config = getAnvilEthConfig();

        uint256 deployerPrivateKey = uint256(vm.envBytes32("PRIVATE_KEY"));
        _deployer = vm.addr(deployerPrivateKey);
        _chainId = uint32(block.chainid);
        _owner = _deployer;

        console2.log("Deployer: ", _deployer);
        console2.log("Chain ID: ", _chainId);
        console2.log("Owner: ", _owner);

        vm.startBroadcast(deployerPrivateKey);

        _defaultIsm = new PausableIsm{salt: _SALT}(_owner);
        console2.log("Deployed PausableIsm at: ", address(_defaultIsm));

        _defaultHook = new TestPostDispatchHook{salt: _SALT}();
        console2.log("Deployed TestPostDispatchHook at: ", address(_defaultHook));

        _mailbox = new Mailbox{salt: _SALT}(_chainId);
        _mailbox.initialize(_owner, address(_defaultIsm), address(_defaultHook), address(_defaultHook));
        console2.log("Deployed Mailbox at: ", address(_mailbox));

        _warpISM = new WarpISM{salt: _SALT}("WarpISM", "1", _owner);
        console2.log("Deployed WarpISM at: ", address(_warpISM));

        _token = new OmniToken{salt: _SALT}(_owner, _owner, "Wrapped POKT", "wPOKT");
        console2.log("Deployed Token at: ", address(_token));

        _mintController = new wPOKTMintController{salt: _SALT}(
            address(_mailbox), address(_token), address(_warpISM), _owner, _mintLimit, _mintPerSecond
        );
        console2.log("Deployed MintController at: ", address(_mintController));

        for (uint256 i = 0; i < _config.validators.length; i++) {
            _warpISM.addValidator(_config.validators[i]);
        }
        console2.log("Validators added to WarpISM");

        _warpISM.setSignerThreshold(_config.signerThreshold);
        console2.log("Signer threshold set to: ", _config.signerThreshold);

        _accountFactory = new AccountFactory{salt: _SALT}();
        console2.log("Deployed AccountFactory at: ", address(_accountFactory));

        _multicall3 = new Multicall3{salt: _SALT}();
        console2.log("Deployed Multicall3 at: ", address(_multicall3));

        _token.grantRole(_token.MINTER_ROLE(), address(_mintController));
        console2.log("MINTER_ROLE granted to MintController");

        vm.stopBroadcast();
    }
}
