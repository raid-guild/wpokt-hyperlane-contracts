// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import {IOmniToken} from "@interfaces/IOmniToken.sol";
import {ERC20Burnable} from "@openzeppelin/token/ERC20/extensions/ERC20Burnable.sol";

contract OmniToken is ERC20, ERC20Burnable, AccessControl, IOmniToken {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    address public mintController;

    constructor(address defaultAdmin, address minter, string memory name, string memory symbol) ERC20(name, symbol) {
        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(MINTER_ROLE, minter);
        mintController = minter;
    }

    /*///////////////////////////////////////////////
    //              ACCESS CONTROL
    ///////////////////////////////////////////////*/

    function updateController(address newController) public onlyRole(DEFAULT_ADMIN_ROLE) {
        mintController = newController;
    }

    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    function burnFrom(address account, uint256 amount)
        public
        override(ERC20Burnable, IOmniToken)
        onlyRole(MINTER_ROLE)
    {
        super.burnFrom(account, amount);
    }

    /*///////////////////////////////////////////////
    //              OVERRIDE
    ///////////////////////////////////////////////*/

    function burn(uint256) public pure override(ERC20Burnable) {
        revert BurnDisabled();
    }
}
