// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {Message} from "@hyperlane/libs/Message.sol";
import {CREATE3Factory} from "@create3/CREATE3Factory.sol";
import {wPOKTMintController} from "@src/wPOKTMintController.sol";
import {Mailbox} from "@hyperlane/Mailbox.sol";
import {OmniToken} from "@src/OmniToken.sol";
import {WarpISM, ECDSA} from "@src/WarpISM.sol";
import "@hyperlane/test/TestPostDispatchHook.sol";
import "@hyperlane/test/TestRecipient.sol";

contract ContractTest is Test {
    address[] public signers;
    address public admin = address(1000);
    bytes32 public minterRole;

    uint256 public limit = 100_000_000;
    uint256 public mintPerSecond = 1_000;

    TestPostDispatchHook defaultHook;
    TestPostDispatchHook overrideHook;
    TestPostDispatchHook requiredHook;

    TestRecipient feeRecipient;

    wPOKTMintController public mintController;
    Mailbox public mailbox;
    OmniToken public token;
    WarpISM public warpISM;

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

    function toCalldata(bytes calldata data) public pure returns (bytes calldata) {
        return data;
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

    function setTypeHashes() public {
        _hashedName = keccak256(bytes(_NAME));
        _hashedVersion = keccak256(bytes(_VERSION));
        _cachedChainId = block.chainid;
        _cachedControllerAddress = address(warpISM);
        _cachedDomainSeparator = buildDomainSeparator();

        console2.log("Hashed Name:");
        console2.logBytes32(_hashedName);
        console2.log("Hashed Version:");
        console2.logBytes32(_hashedVersion);
        console2.log("Chain ID:");
        console2.log(_cachedChainId);
        console2.log("Controller Address:");
        console2.log(_cachedControllerAddress);
        console2.log("Domain Separator:");
        console2.logBytes32(_cachedDomainSeparator);
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
        (
            uint8 version,
            uint32 nonce,
            uint32 originDomain,
            address sender,
            uint32 destinationDomain,
            address recipient,
            bytes memory messageBody
        ) = abi.decode(message, (uint8, uint32, uint32, address, uint32, address, bytes));

        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    MESSAGE_TYPE_HASH, version, nonce, originDomain, sender, destinationDomain, recipient, keccak256(messageBody)
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKeyAsc[signerIndex], digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return signature;
    }

    function buildSignatureDesc(bytes memory message, uint256 signerIndex) public view returns (bytes memory) {
        (
            uint8 version,
            uint32 nonce,
            uint32 originDomain,
            address sender,
            uint32 destinationDomain,
            address recipient,
            bytes memory messageBody
        ) = abi.decode(message, (uint8, uint32, uint32, address, uint32, address, bytes));

        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    MESSAGE_TYPE_HASH,
                    version,
                    nonce,
                    originDomain,
                    sender,
                    destinationDomain,
                    recipient,
                    keccak256(messageBody)
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKeyDesc[signerIndex], digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return signature;
    }

    function buildSignaturesAsc(bytes memory data) public view returns (bytes[] memory) {
        console2.log("Building Ascending Signatures");
        bytes[] memory signatures = new bytes[](privKeyAsc.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            console2.log("Building Signature");
            signatures[i] = buildSignatureAsc(data, i);
        }
        return signatures;
    }

    function buildSignaturesDesc(bytes memory data) public view returns (bytes[] memory) {
        bytes[] memory signatures = new bytes[](privKeyDesc.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            signatures[i] = buildSignatureDesc(data, i);
        }
        return signatures;
    }

    function setUp() public {
        uint256 chainId = block.chainid;
        feeRecipient = new TestRecipient();
        defaultHook = new TestPostDispatchHook();
        requiredHook = new TestPostDispatchHook();
        overrideHook = new TestPostDispatchHook();
        mailbox = new Mailbox(uint32(chainId));

        token = new OmniToken(admin, admin, "OmniToken", "OMNI");
        minterRole = token.MINTER_ROLE();
        warpISM = new WarpISM(_NAME, _VERSION, admin);
        mailbox.initialize(admin, address(warpISM), address(defaultHook), address(requiredHook));
        mintController =
            new wPOKTMintController(address(mailbox), address(token), address(warpISM), admin, limit, mintPerSecond);
        vm.startPrank(admin);
        token.grantRole(minterRole, address(this));
        token.updateController(address(mintController));
        for (uint256 i = 0; i < signers.length; i++) {
            warpISM.addValidator(signers[i]);
        }
        MESSAGE_TYPE_HASH = warpISM.DIGEST_TYPE_HASH();
        setTypeHashes();
        buildValidatorArrayAscending(10);
        buildValidatorArrayDescending(10);

        vm.label(address(warpISM), "WarpISM");
        vm.label(address(token), "Omni Token");
        vm.label(address(mintController), "wPOKT Mint Controller");
        vm.label(address(mailbox), "Mailbox");
        vm.label(admin, "Admin");

        vm.stopPrank();
    }

    function testMint() public {
        console.log("WTF1");
        bytes memory messageBody = buildMessageBody(address(1000), 1000 ether, address(1000));
        bytes memory message = buildMintData(1, 1, 1, address(1000), uint32(_cachedChainId), admin, messageBody);
        console.log("WTF2");
        bytes[] memory signatureArray = buildSignaturesAsc(message);
        console.log("WTF3");
        bytes memory signatures = abi.encode(signatureArray);
        console.log("WTF");
        mintController.fulfillOrder(signatures, message);
    }
}
