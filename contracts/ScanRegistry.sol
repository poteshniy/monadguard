// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title ScanRegistry
/// @notice Permissionless, append-only trust registry for agentic tools
///         (MCP servers / skills). An off-chain scanner produces a verdict,
///         signs it with a P-256 (secp256r1) key derived from a passkey PRF,
///         and anchors it here. The contract VERIFIES that signature on-chain
///         through the RIP-7212 / EIP-7951 `P256VERIFY` precompile at 0x100.
///         You cannot anchor a verdict you did not sign.
///
/// @dev Design notes (read before "simplifying"):
///      - Anchoring is PERMISSIONLESS. Anyone may register a key and attest.
///        Trust derives from *who* attested (msg.sender), not from a gatekept
///        allowlist. Sybil resistance belongs in the query layer.
///      - `toolId` is the tool's stable IDENTITY (keccak256 of canonical
///        kind:origin#name). `contentHash` is the hash of the exact manifest
///        version scanned. One toolId accumulates many contentHashes — that
///        is the trust *history*.
///      - Timestamps come from block.timestamp, never calldata.
///      - History lives in EVENTS (indexed by Envio HyperIndex). Storage holds
///        only the O(1) "latest" pointer needed for on-chain reads.
///      - The signed digest commits to (chainId, registry address, attestor,
///        toolId, contentHash, verdict, score, receiptHash). Without that
///        binding, a signature over an opaque receiptHash would prove only
///        that *some* receipt was signed — an attestor could anchor CLEAN
///        while holding a signature over CRITICAL. Domain separation also
///        stops replay onto another chain or another registry deployment.
///      - `receiptURI` is deliberately NOT in the digest: it is a mutable
///        pointer controlled by the same attestor, so binding it buys nothing
///        and would force a re-sign whenever the receipt is rehosted.
contract ScanRegistry {
    // ─────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────

    /// RIP-7212 / EIP-7951 secp256r1 verifier.
    /// Input: 160 bytes = hash ‖ r ‖ s ‖ pubKeyX ‖ pubKeyY.
    /// Output: 32-byte 1 on success; empty (or 32-byte 0) on failure.
    address public constant P256VERIFY = address(0x100);

    /// 0 = UNKNOWN, 1 = CLEAN, 2 = WARN, 3 = CRITICAL
    uint8 public constant VERDICT_MAX = 3;
    /// Risk score, 0 (clean) .. 100 (maximally dangerous)
    uint16 public constant SCORE_MAX = 100;

    // ─────────────────────────────────────────────────────────────
    // Types
    // ─────────────────────────────────────────────────────────────

    /// Uncompressed secp256r1 public key, split for calldata/precompile use.
    struct PubKey {
        bytes32 x;
        bytes32 y;
    }

    struct Attestation {
        bytes32 contentHash; // manifest version that was scanned
        bytes32 receiptHash; // sha256 of the JCS-canonicalized receipt payload
        uint64 timestamp; // block.timestamp of the anchor
        uint8 verdict; // 0..3
        uint16 score; // 0..100 risk score
        uint32 count; // how many times this attestor anchored this tool
    }

    struct ScanInput {
        bytes32 toolId;
        bytes32 contentHash;
        bytes32 receiptHash;
        uint8 verdict;
        uint16 score;
        bytes32 r; // P-256 signature over anchorDigest(...)
        bytes32 s;
        string receiptURI;
    }

    // ─────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────

    /// toolId => attestor => latest attestation from that attestor
    mapping(bytes32 => mapping(address => Attestation)) public latest;

    /// toolId => total anchors across all attestors
    mapping(bytes32 => uint32) public toolScanCount;

    /// attestor address => the P-256 public key it signs receipts with.
    /// Registration requires proof of possession, so an address cannot claim
    /// another attestor's key and piggyback on its reputation.
    mapping(address => PubKey) public attestorKey;

    /// Global counter — cheap "is this thing alive" metric for the demo.
    uint64 public totalAnchors;

    // ─────────────────────────────────────────────────────────────
    // Events (the actual registry; Envio indexes these)
    // ─────────────────────────────────────────────────────────────

    event ScanAnchored(
        bytes32 indexed toolId,
        address indexed attestor,
        bytes32 indexed contentHash,
        uint8 verdict,
        uint16 score,
        bytes32 receiptHash,
        string receiptURI,
        uint64 timestamp
    );

    event AttestorRegistered(address indexed attestor, bytes32 pubKeyX, bytes32 pubKeyY, string metaURI);

    // ─────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────

    error ZeroToolId();
    error ZeroContentHash();
    error BadVerdict(uint8 verdict);
    error BadScore(uint16 score);
    error EmptyBatch();
    error ZeroKey();
    error UnknownAttestor(address attestor);
    error BadSignature();

    // ─────────────────────────────────────────────────────────────
    // Digests (public so clients can assert parity before signing)
    // ─────────────────────────────────────────────────────────────

    /// @notice Message a key holder must sign to bind its key to `attestor`.
    function registrationDigest(address attestor, bytes32 x, bytes32 y) public view returns (bytes32) {
        return sha256(abi.encodePacked("MonadGuard/register/v1", block.chainid, address(this), attestor, x, y));
    }

    /// @notice Message the attestor signs for one anchor. Commits to every
    ///         field written on-chain, plus the deployment identity.
    function anchorDigest(
        address attestor,
        bytes32 toolId,
        bytes32 contentHash,
        uint8 verdict,
        uint16 score,
        bytes32 receiptHash
    ) public view returns (bytes32) {
        return sha256(
            abi.encodePacked(
                "MonadGuard/anchor/v1",
                block.chainid,
                address(this),
                attestor,
                toolId,
                contentHash,
                verdict,
                score,
                receiptHash
            )
        );
    }

    // ─────────────────────────────────────────────────────────────
    // Write
    // ─────────────────────────────────────────────────────────────

    /// @notice Publish the P-256 key this address signs receipts with.
    /// @param x Public key X coordinate.
    /// @param y Public key Y coordinate.
    /// @param metaURI Optional pointer to scanner metadata (rule set version, docs).
    /// @param r Signature over `registrationDigest(msg.sender, x, y)`.
    /// @param s Signature over `registrationDigest(msg.sender, x, y)`.
    function registerAttestor(bytes32 x, bytes32 y, string calldata metaURI, bytes32 r, bytes32 s) external {
        if (x == bytes32(0) && y == bytes32(0)) revert ZeroKey();
        if (!_verifyP256(registrationDigest(msg.sender, x, y), r, s, x, y)) revert BadSignature();

        attestorKey[msg.sender] = PubKey(x, y);
        emit AttestorRegistered(msg.sender, x, y, metaURI);
    }

    /// @notice Anchor one signed scan result.
    /// @return count This attestor's anchor count for this tool, after the write.
    function anchorScan(
        bytes32 toolId,
        bytes32 contentHash,
        uint8 verdict,
        uint16 score,
        bytes32 receiptHash,
        string calldata receiptURI,
        bytes32 r,
        bytes32 s
    ) external returns (uint32 count) {
        PubKey storage k = attestorKey[msg.sender];
        if (k.x == bytes32(0) && k.y == bytes32(0)) revert UnknownAttestor(msg.sender);

        count = _anchor(toolId, contentHash, verdict, score, receiptHash, receiptURI, r, s, k);
        unchecked {
            totalAnchors += 1;
        }
    }

    /// @notice Anchor many signed scans in one transaction.
    /// @dev Load-bearing: a PRF ceremony needs user verification, so the browser
    ///      derives once, signs N receipts in memory, and anchors them together.
    function anchorScanBatch(ScanInput[] calldata scans) external returns (uint256 written) {
        written = scans.length;
        if (written == 0) revert EmptyBatch();

        PubKey storage k = attestorKey[msg.sender];
        if (k.x == bytes32(0) && k.y == bytes32(0)) revert UnknownAttestor(msg.sender);

        for (uint256 i; i < written;) {
            ScanInput calldata sc = scans[i];
            _anchor(sc.toolId, sc.contentHash, sc.verdict, sc.score, sc.receiptHash, sc.receiptURI, sc.r, sc.s, k);
            unchecked {
                ++i;
            }
        }
        unchecked {
            totalAnchors += uint64(written);
        }
    }

    function _anchor(
        bytes32 toolId,
        bytes32 contentHash,
        uint8 verdict,
        uint16 score,
        bytes32 receiptHash,
        string calldata receiptURI,
        bytes32 r,
        bytes32 s,
        PubKey storage k
    ) internal returns (uint32 count) {
        if (toolId == bytes32(0)) revert ZeroToolId();
        if (contentHash == bytes32(0)) revert ZeroContentHash();
        if (verdict > VERDICT_MAX) revert BadVerdict(verdict);
        if (score > SCORE_MAX) revert BadScore(score);

        bytes32 digest = anchorDigest(msg.sender, toolId, contentHash, verdict, score, receiptHash);
        if (!_verifyP256(digest, r, s, k.x, k.y)) revert BadSignature();

        Attestation storage a = latest[toolId][msg.sender];
        unchecked {
            count = a.count + 1;
        }

        a.contentHash = contentHash;
        a.receiptHash = receiptHash;
        a.timestamp = uint64(block.timestamp);
        a.verdict = verdict;
        a.score = score;
        a.count = count;

        unchecked {
            toolScanCount[toolId] += 1;
        }

        emit ScanAnchored(
            toolId, msg.sender, contentHash, verdict, score, receiptHash, receiptURI, uint64(block.timestamp)
        );
    }

    // ─────────────────────────────────────────────────────────────
    // Precompile
    // ─────────────────────────────────────────────────────────────

    /// @dev Returns false on a failed staticcall, on empty returndata (the
    ///      RIP-7212 failure encoding) and on an explicit 0 — never reverts,
    ///      so callers get `BadSignature` rather than an opaque bubble-up.
    function _verifyP256(bytes32 digest, bytes32 r, bytes32 s, bytes32 x, bytes32 y)
        internal
        view
        returns (bool)
    {
        (bool ok, bytes memory out) = P256VERIFY.staticcall(abi.encodePacked(digest, r, s, x, y));
        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
    }

    /// @notice Exposed so the client can check the precompile is live on this
    ///         chain before the demo, instead of discovering it in a revert.
    function verifySignature(bytes32 digest, bytes32 r, bytes32 s, bytes32 x, bytes32 y)
        external
        view
        returns (bool)
    {
        return _verifyP256(digest, r, s, x, y);
    }

    // ─────────────────────────────────────────────────────────────
    // Read (for other contracts / cheap RPC checks)
    // ─────────────────────────────────────────────────────────────

    /// @notice Latest verdict a specific attestor gave a tool.
    /// @dev timestamp == 0 means "never attested by this attestor".
    function latestVerdict(bytes32 toolId, address attestor)
        external
        view
        returns (uint8 verdict, uint16 score, uint64 timestamp, bytes32 contentHash)
    {
        Attestation storage a = latest[toolId][attestor];
        return (a.verdict, a.score, a.timestamp, a.contentHash);
    }

    /// @notice Guard helper: has `attestor` cleared this exact manifest version,
    ///         and is that clearance younger than `maxAge` seconds?
    function isCleared(bytes32 toolId, bytes32 contentHash, address attestor, uint64 maxAge)
        external
        view
        returns (bool)
    {
        Attestation storage a = latest[toolId][attestor];
        return a.timestamp != 0 && a.verdict == 1 && a.contentHash == contentHash
            && block.timestamp - a.timestamp <= maxAge;
    }

    function isKnown(bytes32 toolId) external view returns (bool) {
        return toolScanCount[toolId] != 0;
    }

    function isRegistered(address attestor) external view returns (bool) {
        PubKey storage k = attestorKey[attestor];
        return k.x != bytes32(0) || k.y != bytes32(0);
    }
}
