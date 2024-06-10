// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.20;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IWarpISM} from "@interfaces/IWarpISM.sol";
import {Message} from "@hyperlane/libs/Message.sol";

contract WarpISM is EIP712, IWarpISM, Ownable {
    using Message for bytes;
    using ECDSA for bytes32;

    mapping(address => bool) public validators;

    uint256 public validatorCount;
    uint256 public signerThreshold = 50; // out of 100

    uint256 public constant SIGNATURE_SIZE = 65;

    bytes32 public constant DIGEST_TYPE_HASH = keccak256(
        "Message(uint8 version,uint32 nonce,uint32 originDomain,bytes32 sender,uint32 destinationDomain,bytes32 recipient,bytes messageBody)"
    );

    constructor(string memory name_, string memory version_, address initialOwner_)
        EIP712(name_, version_)
        Ownable(initialOwner_)
    {}

    /*//////////////////////////////////////////////////////////////
    // Public View
    //////////////////////////////////////////////////////////////*/

    function verify(bytes calldata metadata, bytes calldata message) external view returns (bool success) {
        success = _verify(metadata, message);
    }

    function getDigest(bytes calldata message) public view returns (bytes32 digest) {
        digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    DIGEST_TYPE_HASH,
                    message.version(),
                    message.nonce(),
                    message.origin(),
                    message.sender(),
                    message.destination(),
                    message.recipient(),
                    keccak256(message.body())
                )
            )
        );
    }

    // @dev Separates aggregated signatures into an array of individual signatures
    function getSignatures(bytes calldata metadata) public pure returns (bytes[] memory signatures) {
        if (metadata.length % SIGNATURE_SIZE != 0) {
            revert InvalidSignatureLength();
        }
        uint256 signatureCount = metadata.length / SIGNATURE_SIZE;
        signatures = new bytes[](signatureCount);
        for (uint256 i = 0; i < signatureCount; i++) {
            bytes memory signature = new bytes(SIGNATURE_SIZE);
            for (uint256 j = 0; j < SIGNATURE_SIZE; j++) {
                signature[j] = metadata[i * SIGNATURE_SIZE + j];
            }
            signatures[i] = signature;
        }
    }

    /*//////////////////////////////////////////////////////////////
    // Internal
    //////////////////////////////////////////////////////////////*/

    function _verify(bytes calldata metadata, bytes calldata message) internal view returns (bool) {
        bytes32 digest = getDigest(message);
        bytes[] memory signatures = getSignatures(metadata);

        address lastSigner;
        address currentSigner;

        uint256 validSignatures = 0;
        uint256 signatureCount = signatures.length;

        if (signatureCount < signerThreshold) {
            revert InvalidSignatures();
        }

        for (uint256 i = 0; i < signatureCount; i++) {
            currentSigner = digest.recover(signatures[i]);
            if (validators[currentSigner] && currentSigner > lastSigner) {
                validSignatures++;
                lastSigner = currentSigner;
            }
            unchecked {
                ++i;
            }
        }
        return validSignatures > 0 && validSignatures >= signerThreshold;
    }

    /*//////////////////////////////////////////////////////////////
    // Access Control
    //////////////////////////////////////////////////////////////*/

    /// @notice Adds a validator to the list of validators.
    /// @dev Can only be called by admin.
    /// Emits a NewValidator event upon successful addition.
    /// @param validator The address of the validator to add.
    function addValidator(address validator) external onlyOwner {
        if (validator == address(0)) {
            revert NonZero();
        }
        if (validators[validator] == true) {
            revert InvalidAddValidator();
        }
        validators[validator] = true;
        validatorCount++;
        emit NewValidator(validator);
    }

    /// @notice Removes a validator from the list of validators.
    /// @dev Can only be called by admin.
    /// Emits a RemovedValidator event upon successful removal.
    /// @param validator The address of the validator to remove.
    function removeValidator(address validator) external onlyOwner {
        if (validatorCount - 1 < signerThreshold) {
            revert BelowMinThreshold();
        }
        if (validator == address(0)) {
            revert NonZero();
        }
        if (validators[validator] == false) {
            revert InvalidRemoveValidator();
        }
        validators[validator] = false;
        validatorCount--;
        emit RemovedValidator(validator);
    }

    /// @notice Sets the signature ratio.
    /// @dev Can only be called by admin.
    /// Emits a SignerThresholdSet event upon successful setting.
    /// @param signatureRatio The new signature ratio to set.
    function setSignerThreshold(uint256 signatureRatio) external onlyOwner {
        if (signatureRatio > validatorCount || signatureRatio == 0 || validatorCount / 2 > signatureRatio) {
            revert InvalidSignatureRatio();
        }
        signerThreshold = signatureRatio;
        emit SignerThresholdSet(signatureRatio);
    }
}
