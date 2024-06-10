// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.20;

import {ERC20} from "@open-zeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@open-zeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Permit} from "@open-zeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20Pausable} from "@open-zeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import {AccessControl} from "@open-zeppelin/contracts/access/AccessControl.sol";
import {IOmniToken} from "@interfaces/IOmniToken.sol";

contract OmniToken is ERC20, ERC20Burnable, ERC20Pausable, AccessControl, ERC20Permit, IOmniToken {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    address public mintController;

    constructor(address defaultAdmin, address pauser, string memory name, string memory symbol)
        ERC20(name, symbol)
        ERC20Permit(name)
    {
        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(PAUSER_ROLE, pauser);
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

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /*///////////////////////////////////////////////
    //              OVERRIDE
    ///////////////////////////////////////////////*/

    function burn(uint256) public pure override(ERC20Burnable) {
        revert BurnDisabled();
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual override (ERC20Pausable, ERC20) {
        super._beforeTokenTransfer(from, to, amount);

    }
}
