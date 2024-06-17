// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {Message} from "@hyperlane/libs/Message.sol";
import {MessageMock} from "./mocks/MessageMock.sol";
import {TypeCasts} from "@hyperlane/libs/TypeCasts.sol";
import {CREATE3Factory} from "@create3/CREATE3Factory.sol";
import {wPOKTMintController} from "@src/wPOKTMintController.sol";
import {Mailbox} from "@hyperlane/Mailbox.sol";
import {OmniToken} from "@src/OmniToken.sol";
import {WarpISM, ECDSA} from "@src/WarpISM.sol";
import {IWarpISM} from "@interfaces/IWarpISM.sol";
import {IInterchainSecurityModule} from "@hyperlane/interfaces/IInterchainSecurityModule.sol";
import "@hyperlane/test/TestPostDispatchHook.sol";
import "@hyperlane/test/TestRecipient.sol";

contract BaseTest is Test {
    using Message for bytes;
    using TypeCasts for bytes32;
    using TypeCasts for address;

    address[] public signers;
    address public admin = address(1000);
    bytes32 public minterRole;

    uint256 public limit = 100_000_000;
    uint256 public mintPerSecond = 1_000;

    TestPostDispatchHook defaultHook;
    TestPostDispatchHook overrideHook;
    TestPostDispatchHook requiredHook;

    MessageMock public _message;

    TestRecipient feeRecipient;

    wPOKTMintController public mintController;
    Mailbox public mailbox;
    OmniToken public token;
    WarpISM public warpISM;

    bytes public globalMessage;

    string public constant _NAME = "WarpISM";
    string public constant _VERSION = "1.0";

    // Signing
    bytes32 private constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public MESSAGE_TYPE_HASH;
    address[] internal validAddressAsc;
    address[] internal validAddressDesc;
    uint256[] internal privKeyAsc;
    uint256[] internal privKeyDesc;
    bytes32 internal _hashedName;
    bytes32 internal _hashedVersion;
    uint256 internal _cachedChainId;
    bytes32 internal _cachedDomainSeparator;
    address internal _cachedControllerAddress;

    function buildMintData(
        uint8 version,
        uint32 nonce,
        uint32 originDomain,
        address sender,
        uint32 destinationDomain,
        address recipient,
        bytes memory messageBody
    ) public pure returns (bytes memory) {
        return abi.encodePacked(
            version,
            nonce,
            originDomain,
            bytes32(uint256(uint160(sender))),
            destinationDomain,
            bytes32(uint256(uint160(recipient))),
            messageBody
        );
    }

    function buildMessageBody(address recipient, uint256 amount, address sender) public pure returns (bytes memory) {
        return abi.encode(recipient, amount, sender);
    }

    function buildValidatorArrayAscending(uint256 quantity) public {
        uint256[] memory privateKeyArrayAscending = new uint256[](quantity);
        address[] memory validatorArrayAscending = new address[](quantity);
        for (uint256 i = 0; i < quantity; i++) {
            address newSignerAddress = vm.addr(i + 1);
            validatorArrayAscending[i] = newSignerAddress;
            privateKeyArrayAscending[i] = i + 1;
        }
        for (uint256 i = 0; i < quantity; i++) {
            for (uint256 j = 0; j < quantity - i - 1; j++) {
                if (validatorArrayAscending[j] > validatorArrayAscending[j + 1]) {
                    address tempAddress = validatorArrayAscending[j];
                    uint256 tempKey = privateKeyArrayAscending[j];
                    validatorArrayAscending[j] = validatorArrayAscending[j + 1];
                    privateKeyArrayAscending[j] = privateKeyArrayAscending[j + 1];
                    validatorArrayAscending[j + 1] = tempAddress;
                    privateKeyArrayAscending[j + 1] = tempKey;
                }
            }
        }
        for (uint256 i = 0; i < quantity; i++) {
            privKeyAsc.push(privateKeyArrayAscending[i]);
            validAddressAsc.push(validatorArrayAscending[i]);
        }
    }

    function buildValidatorArrayDescending(uint256 quantity) public {
        uint256[] memory privateKeyArrayDescending = new uint256[](quantity);
        address[] memory validatorArrayDescending = new address[](quantity);
        for (uint256 i = 0; i < quantity; i++) {
            address newSignerAddress = vm.addr(i + 1);
            validatorArrayDescending[i] = newSignerAddress;
            privateKeyArrayDescending[i] = i + 1;
        }
        for (uint256 i = 0; i < quantity; i++) {
            for (uint256 j = 0; j < quantity - i - 1; j++) {
                if (validatorArrayDescending[j] < validatorArrayDescending[j + 1]) {
                    address tempAddress = validatorArrayDescending[j];
                    uint256 tempKey = privateKeyArrayDescending[j];
                    validatorArrayDescending[j] = validatorArrayDescending[j + 1];
                    privateKeyArrayDescending[j] = privateKeyArrayDescending[j + 1];
                    validatorArrayDescending[j + 1] = tempAddress;
                    privateKeyArrayDescending[j + 1] = tempKey;
                }
            }
        }
        for (uint256 i = 0; i < quantity; i++) {
            privKeyDesc.push(privateKeyArrayDescending[i]);
            validAddressDesc.push(validatorArrayDescending[i]);
        }
    }

    function getDigest(bytes memory message) public view returns (bytes32 digest) {
        digest = warpISM.getDigest(message);
    }

    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
        return ECDSA.toTypedDataHash(_cachedDomainSeparator, structHash);
    }

    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) public pure returns (bytes32 data) {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "\x19\x01")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            data := keccak256(ptr, 0x42)
        }
    }

    function buildDomainSeparator() public view returns (bytes32) {
        return
            keccak256(abi.encode(DOMAIN_TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(mintController)));
    }

    function buildSignatureAsc(bytes memory message, uint256 signerIndex) public view returns (bytes memory) {
        bytes32 digest = warpISM.getDigest(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKeyAsc[signerIndex], digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return signature;
    }

    function buildSignatureDesc(bytes memory message, uint256 signerIndex) public view returns (bytes memory) {
        bytes32 digest = warpISM.getDigest(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKeyDesc[signerIndex], digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return signature;
    }

    function buildSignaturesAsc(bytes memory data) public view returns (bytes[] memory) {
        bytes[] memory signatures = new bytes[](privKeyAsc.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            bytes memory signature = buildSignatureAsc(data, i);
            signatures[i] = signature;
        }
        return signatures;
    }

    function encodeSignatures(bytes[] memory signatures) public pure returns (bytes memory) {
        require(signatures.length == 10, "There must be exactly 10 signatures");

        bytes memory concatenatedSignatures;
        for (uint256 i = 0; i < signatures.length; i++) {
            require(signatures[i].length == 65, "Each signature must be 65 bytes long");
            concatenatedSignatures = abi.encodePacked(concatenatedSignatures, signatures[i]);
        }

        return concatenatedSignatures;
    }

    function buildSignaturesDesc(bytes memory data) public view returns (bytes[] memory) {
        bytes[] memory signatures = new bytes[](privKeyDesc.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            signatures[i] = buildSignatureDesc(data, i);
        }
        return signatures;
    }

    function setUp() public virtual {
        uint256 chainId = block.chainid;
        feeRecipient = new TestRecipient();
        defaultHook = new TestPostDispatchHook();
        requiredHook = new TestPostDispatchHook();
        overrideHook = new TestPostDispatchHook();
        mailbox = new Mailbox(uint32(chainId));

        _message = new MessageMock();

        buildValidatorArrayAscending(10);
        buildValidatorArrayDescending(10);

        token = new OmniToken(admin, admin, "OmniToken", "OMNI");
        minterRole = token.MINTER_ROLE();
        warpISM = new WarpISM(_NAME, _VERSION, admin);
        mailbox.initialize(admin, address(warpISM), address(defaultHook), address(requiredHook));
        mintController =
            new wPOKTMintController(address(mailbox), address(token), address(warpISM), admin, limit, mintPerSecond);
        vm.startPrank(admin);
        token.grantRole(minterRole, address(mintController));
        token.updateController(address(mintController));
        for (uint256 i = 0; i < validAddressAsc.length; i++) {
            warpISM.addValidator(validAddressAsc[i]);
        }
        MESSAGE_TYPE_HASH = warpISM.DIGEST_TYPE_HASH();

        vm.label(address(warpISM), "WarpISM");
        vm.label(address(token), "Omni Token");
        vm.label(address(mintController), "wPOKT Mint Controller");
        vm.label(address(mailbox), "Mailbox");
        vm.label(admin, "Admin");

        vm.stopPrank();
    }

    function testMint() public {
        uint8 version = mailbox.VERSION();
        bytes memory messageBody = buildMessageBody(address(1000), 1000 ether, address(1000));
        bytes memory message =
            buildMintData(version, 1, 1, address(1000), mailbox.localDomain(), address(mintController), messageBody);
        bytes[] memory signatureArray = buildSignaturesAsc(message);
        bytes memory concatenatedSignatures = encodeSignatures(signatureArray);
        mintController.fulfillOrder(concatenatedSignatures, message);
    }
}
