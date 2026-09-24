// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice The part of ScanRegistry a consumer needs. Nothing else is required:
///         no token, no registration, no permission from us.
interface IScanRegistry {
    function isCleared(bytes32 toolId, bytes32 contentHash, address attestor, uint64 maxAge)
        external view returns (bool);
    function latestVerdict(bytes32 toolId, address attestor)
        external view returns (uint8 verdict, uint16 score, uint64 timestamp, bytes32 contentHash);
}

/// @title  Example: refuse to route a call to an agent tool that nobody has cleared.
/// @notice The point of anchoring verdicts on-chain rather than in a database:
///         another contract can make the check itself, in the same transaction,
///         without trusting an API to answer honestly.
///
///         The consumer picks its own attestors. MonadGuard does not decide who
///         is trustworthy — the registry records who said what, and this contract
///         decides whose word it takes.
contract GatedRouter {
    IScanRegistry public immutable registry;
    address public immutable attestor;   // whose verdict this router accepts
    uint64  public immutable maxAge;     // a stale clearance is not a clearance

    error ToolNotCleared(bytes32 toolId, bytes32 contentHash);

    constructor(IScanRegistry registry_, address attestor_, uint64 maxAge_) {
        registry = registry_;
        attestor = attestor_;
        maxAge = maxAge_;
    }

    /// @param toolId      stable identity: keccak256("mcp:<origin>#<name>")
    /// @param contentHash keccak256 of the exact manifest the agent is about to use.
    ///                    Pinning it is the whole point: a tool that was clean last
    ///                    week can ship a poisoned manifest today (rug pull).
    function callTool(bytes32 toolId, bytes32 contentHash, address target, bytes calldata data)
        external
        returns (bytes memory)
    {
        if (!registry.isCleared(toolId, contentHash, attestor, maxAge)) {
            revert ToolNotCleared(toolId, contentHash);
        }
        (bool ok, bytes memory out) = target.call(data);
        require(ok, "tool call failed");
        return out;
    }

    /// @notice Read-only variant for agents that want the score, not a revert.
    function riskOf(bytes32 toolId) external view returns (uint8 verdict, uint16 score, uint64 at) {
        (verdict, score, at, ) = registry.latestVerdict(toolId, attestor);
    }
}
