// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.20;

import {IMailbox} from "@hyperlane/interfaces/IMailbox.sol";
import {IInterchainSecurityModule} from "@hyperlane/interfaces/IInterchainSecurityModule.sol";
import {Message} from "@hyperlane/libs/Message.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IOmniToken} from "@interfaces/IOmniToken.sol";
import {IWarpController} from "@interfaces/IWarpController.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

abstract contract WarpMintController is AccessControl, IMailbox, IOmniToken, IWarpController {
    using Message for bytes;

    bytes32 public constant MAIL_BOX_ROLE = keccak256("MAIL_BOX_ROLE");

    IMailbox private _mailbox;
    IOmniToken private _token;
    IInterchainSecurityModule private _ism;

    constructor(address mailbox_, address token_, address ism_, address defaultAdmin) {
        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(MAIL_BOX_ROLE, mailbox_);
        _mailbox = IMailbox(mailbox_);
        _token = IOmniToken(token_);
        _ism = IInterchainSecurityModule(ism_);
    }

    /*///////////////////////////////////////////////
    //              ACCESS CONTROL
    ///////////////////////////////////////////////*/

    // @notice This function allows the mailbox contract to fulfill the order after authenticating through the ISM
    // @param _messageBody The message body
    function handle(uint32, bytes32, bytes calldata _messageBody) external onlyRole(MAIL_BOX_ROLE) {
        // Decode the message body
        (address recipient, uint256 amount,) = abi.decode(_messageBody, (address, uint256, address));
        // Mint the tokens to the recipient
        _token.mint(recipient, amount);
    }

    // @notice This function allows the admin to change the inter-chain security module
    // @param ism_ The new interchain security module contract address
    function setIsm(address ism_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _ism = IInterchainSecurityModule(ism_);
    }

    /*///////////////////////////////////////////////
    //              PUBLIC MUTATIVE
    ///////////////////////////////////////////////*/
    // @notice This function allows the controller to fulfill the order
    // @param metadata The signed message signatures metadata
    // @param message The complete unsigned message
    function fulfillOrder(bytes calldata metadata, bytes calldata message) public virtual {
        // Process the message through the mailbox and interchain security module
        // Note that the mailbox already checks that the message is not a duplicate
        // Mailbox will callback to the `interchainSecurityModule` method and then this contract's `handle` function
        _mailbox.process(metadata, message);
        // Get the message ID
        bytes32 orderId = message.id();
        // Emit the fulfillment event
        emit Fulfillment(orderId, message);
    }

    // @notice This function allows the controller to initiate the order
    // @param destinationDomain The destination domain and/or chainId
    // @param recipientAddress The receiving warp controller address
    // @param messageBody The message body
    function initiateOrder(uint32 destinationDomain, bytes32 recipientAddress, bytes calldata messageBody)
        public
        virtual
    {
        (, uint256 amount, address sender) = abi.decode(messageBody, (address, uint256, address));
        _token.burnFrom(sender, amount);
        // Initiate the order through the mailbox
        // The backend consumes the dispatch event emitted by the mailbox
        _mailbox.dispatch(destinationDomain, recipientAddress, messageBody);
    }

    /*///////////////////////////////////////////////
    //              PUBLIC VIEW
    ///////////////////////////////////////////////*/
    // @notice This function returns the ism contract interface
    function interchainSecurityModule() external view returns (IInterchainSecurityModule) {
        return _ism;
    }
}