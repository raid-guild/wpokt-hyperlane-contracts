// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.20;

interface IWarpISM {
    // Data object for signing and digest construction
    struct MintData {
        address recipient;
        uint256 amount;
        uint256 nonce;
    }

    error InvalidSignatureRatio();
    error InvalidSignatures();
    error InvalidRemoveValidator();
    error InvalidAddValidator();
    error InvalidSignatureLength();
    error BelowMinThreshold();
    error NonZero();

    event NewValidator(address indexed validator);
    event RemovedValidator(address indexed validator);
    event SignerThresholdSet(uint256 indexed ratio);
}
