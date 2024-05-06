pragma solidity ^0.8.20;

interface IOmniToken {
    // Standard burning by message sender is disabled.  Only the minter can burn tokens.
    error BurnDisabled();

    /**
     * @notice Initiates a multi-chain transfer by burning tokens on the source chain
     * @param account Address of sender on source chain
     * @param amount Amount of tokens to burn
     */
    function burnFrom(address account, uint256 amount) external;

    /**
     * @notice Fulfills a multi-chain transfer by minting tokens on the destination chain
     * @param to Address of recipient on destination chain
     * @param amount Amount of tokens to mint
     */
    function mint(address to, uint256 amount) external;
}
