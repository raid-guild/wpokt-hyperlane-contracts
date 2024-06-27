// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.20;

interface IWarpISM {
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
}
