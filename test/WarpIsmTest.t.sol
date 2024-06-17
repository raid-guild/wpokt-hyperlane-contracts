pragma solidity ^0.8.20;

import {BaseTest} from "./BaseTest.t.sol";
import {IInterchainSecurityModule} from "@hyperlane/interfaces/IInterchainSecurityModule.sol";

contract WarpIsmTest is BaseTest {

    error InvalidSignatureRatio();
    error InvalidSignatures();
    error InvalidRemoveValidator();
    error InvalidAddValidator();
    error InvalidSignatureLength();
    error BelowMinThreshold();
    error NonZero();
    error InvalidDestination();

    function setUp() public virtual override {
      super.setUp();
    }

    function testGetISM() public view {
        IInterchainSecurityModule ism = mintController.interchainSecurityModule();
        assertEq(address(ism), address(warpISM));
    }

    function testSetValidator() public {
        address newValidator = address(0x123);
        vm.prank(admin);
        warpISM.addValidator(newValidator);
        bool expected = true;
        bool actual = warpISM.validators(newValidator);
        assertEq(expected, actual);
    }

    function testRemoveValidator() public {
        address newValidator = address(0x123);
        vm.prank(admin);
        warpISM.addValidator(newValidator);
        bool expected = true;
        bool actual = warpISM.validators(newValidator);
        assertEq(expected, actual);
        vm.prank(admin);
        warpISM.removeValidator(newValidator);
        expected = false;
        actual = warpISM.validators(newValidator);
        assertEq(expected, actual);
    }

    function testValidatorCount() public {
        uint256 count = warpISM.validatorCount();
        assertEq(count, 10);
    }

    function testSignerThreshold() public {
        uint256 threshold = warpISM.signerThreshold();
        assertEq(threshold, 7);
    }

    function testSignatureSize() public {
        uint256 size = warpISM.SIGNATURE_SIZE();
        assertEq(size, 65);
    }

    function testDigestTypeHash() public {
        bytes32 expected = keccak256(
        "Message(uint8 version,uint32 nonce,uint32 originDomain,bytes32 sender,uint32 destinationDomain,bytes32 recipient,bytes messageBody)"
        );

        bytes32 actual = warpISM.DIGEST_TYPE_HASH();
        assertEq(expected, actual);
    }

    function testSetSignerThreshold() public {
        uint256 newThreshold = 5;
        vm.prank(admin);
        warpISM.setSignerThreshold(newThreshold);
        uint256 actual = warpISM.signerThreshold();
        assertEq(newThreshold, actual);
    }

    function testAddValidatorRevertIfZeroAddress() public {
        address zeroAddress = address(0);
        vm.prank(admin);
        vm.expectRevert(NonZero.selector);
        warpISM.addValidator(zeroAddress);
    }

    function testAddValidatorRevertIfAlreadyAdded() public {
        address validator = address(0x999);
        vm.startPrank(admin);
        warpISM.addValidator(validator); // Adding first time should succeed
        vm.expectRevert(InvalidAddValidator.selector);
        warpISM.addValidator(validator); // Adding second time should revert
        vm.stopPrank();
    }

    function testInvalidSignatureRatio() public {
        // Set the signerThreshold to 2
        vm.prank(admin);
        vm.expectRevert(InvalidSignatureRatio.selector);
        warpISM.setSignerThreshold(2);
    }

    function testRemoveValidatorRevertIfZeroAddress() public {
        vm.expectRevert(NonZero.selector);
        vm.prank(admin);
        warpISM.removeValidator(address(0));
    }

    function testRemoveValidatorRevertIfNotAdded() public {
        vm.prank(admin);
        address nonValidator = address(3);
        vm.expectRevert(InvalidRemoveValidator.selector);
        warpISM.removeValidator(nonValidator);
    }

    function testRemoveValidatorsBelowThreshold() public {
        // Set the signerThreshold to 10
        vm.prank(admin);
        warpISM.setSignerThreshold(10);
        vm.expectRevert(BelowMinThreshold.selector);
        vm.prank(admin);
        warpISM.removeValidator(validAddressAsc[0]);
    }

}