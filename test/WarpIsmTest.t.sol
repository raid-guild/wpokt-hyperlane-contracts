pragma solidity ^0.8.20;

import {BaseTest} from "./BaseTest.t.sol";
import {IInterchainSecurityModule} from "@hyperlane/interfaces/IInterchainSecurityModule.sol";

contract WarpIsmTest is BaseTest {

    error InvalidSignatureRatio();
    error CountBelowThreshold();
    error InvalidRemoveValidator();
    error InvalidAddValidator();
    error InvalidSignatureLength();
    error BelowMinThreshold();
    error NonZero();
    error InvalidDestination();

    event NewValidator(address indexed validator);
    event RemovedValidator(address indexed validator);
    event SignerThresholdSet(uint256 indexed ratio);

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
        vm.expectEmit();
        emit NewValidator(newValidator);
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
        vm.expectEmit();
        emit RemovedValidator(newValidator);
        warpISM.removeValidator(newValidator);
        expected = false;
        actual = warpISM.validators(newValidator);
        assertEq(expected, actual);
    }

    function testValidatorCount() public view {
        uint256 count = warpISM.validatorCount();
        assertEq(count, 10);
    }

    function testSignerThreshold() public view {
        uint256 threshold = warpISM.signerThreshold();
        assertEq(threshold, 7);
    }

    function testSignatureSize() public view {
        uint256 size = warpISM.SIGNATURE_SIZE();
        assertEq(size, 65);
    }

    function testDigestTypeHash() public view {
        bytes32 expected = keccak256(
        "Message(uint8 version,uint32 nonce,uint32 originDomain,bytes32 sender,uint32 destinationDomain,bytes32 recipient,bytes messageBody)"
        );

        bytes32 actual = warpISM.DIGEST_TYPE_HASH();
        assertEq(expected, actual);
    }

    function testSetSignerThreshold() public {
        uint256 newThreshold = 5;
        vm.prank(admin);
        vm.expectEmit();
        emit SignerThresholdSet(newThreshold);
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

    function testGetDigest() public view {
        uint8 version = mailbox.VERSION();
        bytes memory messageBody = buildMessageBody(address(1000), 1000 ether, address(1000));
        bytes memory message =
            buildMintData(version, 1, 1, address(1000), mailbox.localDomain(), address(mintController), messageBody);
        bytes32 digest = warpISM.getDigest(message);
        uint256 expected = uint256(digest);
        assert(expected > 0);
    }

    function testVerify() public view {
        uint8 version = mailbox.VERSION();
        bytes memory messageBody = buildMessageBody(address(1000), 1000 ether, address(1000));
        bytes memory message =
            buildMintData(version, 1, 1, address(1000), mailbox.localDomain(), address(mintController), messageBody);
        bytes[] memory signatureArray = buildSignaturesAsc(message);
        bytes memory concatenatedSignatures = encodeSignatures(signatureArray);
        bool success = warpISM.verify(concatenatedSignatures, message);
        assert(success);
    }

    function testInvalidSignatureLength() public {
        uint8 version = mailbox.VERSION();
        bytes memory messageBody = buildMessageBody(address(1000), 1000 ether, address(1000));
        bytes memory message =
            buildMintData(version, 1, 1, address(1000), mailbox.localDomain(), address(mintController), messageBody);
        bytes[] memory signatureArray = buildSignaturesAsc(message);
        bytes memory concatenatedSignatures = encodeSignatures(signatureArray);
        concatenatedSignatures = abi.encodePacked(concatenatedSignatures, uint8(1));
        vm.expectRevert(InvalidSignatureLength.selector);
        warpISM.verify(concatenatedSignatures, message);
    }

    function testGetSignatures() public view {
        uint8 version = mailbox.VERSION();
        bytes memory messageBody = buildMessageBody(address(1000), 1000 ether, address(1000));
        bytes memory message =
            buildMintData(version, 1, 1, address(1000), mailbox.localDomain(), address(mintController), messageBody);
        bytes[] memory signatureArray = buildSignaturesAsc(message);
        bytes memory concatenatedSignatures = encodeSignatures(signatureArray);
        bytes[] memory signatures = warpISM.getSignatures(concatenatedSignatures);
        assertEq(signatures.length, concatenatedSignatures.length / warpISM.SIGNATURE_SIZE());
    }

    function testBelow() public view {
        uint8 version = mailbox.VERSION();
        bytes memory messageBody = buildMessageBody(address(1000), 1000 ether, address(1000));
        bytes memory message =
            buildMintData(version, 1, 1, address(1000), mailbox.localDomain(), address(mintController), messageBody);
        bytes[] memory signatureArray = buildSignaturesAsc(message);
        bytes memory concatenatedSignatures = encodeSignatures(signatureArray);
        bytes[] memory signatures = warpISM.getSignatures(concatenatedSignatures);
        assertEq(signatures.length, concatenatedSignatures.length / warpISM.SIGNATURE_SIZE());
    }

    function testCountBelowThreshold() public {
        uint8 version = mailbox.VERSION();
        bytes memory messageBody = buildMessageBody(address(1000), 1000 ether, address(1000));
        bytes memory message =
            buildMintData(version, 1, 1, address(1000), mailbox.localDomain(), address(mintController), messageBody);
        bytes[] memory signatureArray = buildSignaturesAsc(message);
        bytes[] memory halfSignatureArray = new bytes[](signatureArray.length / 2);
        for (uint256 i = 0; i < halfSignatureArray.length; i++) {
            halfSignatureArray[i] = signatureArray[i];
        }
        bytes memory concatenatedSignatures = encodeSignatures(halfSignatureArray);
        vm.expectRevert(CountBelowThreshold.selector);
        warpISM.verify(concatenatedSignatures, message);
    }

    function testEIPDomain() public {
        (bytes1 fields, string memory name, string memory version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] memory extensions) = warpISM.eip712Domain();
        assertEq(fields, hex"0f");
        assertEq(name, "WarpISM");
        assertEq(version, "1.0");
        assertEq(chainId, 31337);
        assertEq(verifyingContract, address(warpISM));
        assertEq(salt, bytes32(0));
        assertEq(extensions.length, 0);
    }

    function testOwner() public {
        address owner = warpISM.owner();
        assertEq(owner, admin);
    }

}