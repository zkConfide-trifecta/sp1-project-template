// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @title ZkConfideBettingMarket
/// @notice Verifies zkVM proofs of bet processing (odds, result, settlement)
contract ZkConfideBettingMarket {
    /// @notice SP1 verifier contract address
    address public verifier;

    /// @notice Verification key for the zkVM betting program
    bytes32 public bettingProgramVKey;

    /// @notice Identifier for this betting market (e.g., event hash)
    bytes32 public marketId;

    constructor(
        address _verifier,
        bytes32 _bettingProgramVKey,
        bytes32 _marketId
    ) {
        verifier = _verifier;
        bettingProgramVKey = _bettingProgramVKey;
        marketId = _marketId;
    }

    /// @notice Verifies a proof of a bet outcome processed off-chain
    /// @param _publicValues ABI-encoded public values: (marketId, user, option, amount, payout)
    /// @param _proofBytes SP1 proof bytes generated off-chain
    function verifyBetOutcome(bytes calldata _publicValues, bytes calldata _proofBytes)
        public
        view
        returns (address user, uint8 option, uint256 amount, uint256 payout)
    {
        // Verify the SP1 zk-proof
        ISP1Verifier(verifier).verifyProof(bettingProgramVKey, _publicValues, _proofBytes);

        // Decode public values
        (bytes32 _marketId, address _user, uint8 _option, uint256 _amount, uint256 _payout) =
            abi.decode(_publicValues, (bytes32, address, uint8, uint256, uint256));

        // Ensure the market ID matches
        require(_marketId == marketId, "Invalid market");

        return (_user, _option, _amount, _payout);
    }
}
