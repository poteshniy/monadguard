import { indexer } from "envio";
import type { Tool, ToolVersion, Scan, Attestor } from "envio";

const VERDICT_CLEAN = 1;
const VERDICT_WARN = 2;
const VERDICT_CRITICAL = 3;

indexer.onEvent(
  { contract: "ScanRegistry", event: "AttestorRegistered" },
  async ({ event, context }) => {
    const id = event.params.attestor.toLowerCase();
    const prev: Attestor | undefined = await context.Attestor.get(id);
    context.Attestor.set({
      id,
      pubKeyX: event.params.pubKeyX,
      pubKeyY: event.params.pubKeyY,
      metaURI: event.params.metaURI,
      registeredAt: BigInt(event.block.timestamp),
      scanCount: prev?.scanCount ?? 0,
      toolsCovered: prev?.toolsCovered ?? 0,
    });
  },
);

indexer.onEvent(
  { contract: "ScanRegistry", event: "ScanAnchored" },
  async ({ event, context }) => {
    const toolId = event.params.toolId;
    const attestorId = event.params.attestor.toLowerCase();
    const contentHash = event.params.contentHash;
    const verdict = Number(event.params.verdict);
    const score = Number(event.params.score);
    const ts = BigInt(event.params.timestamp);
    const versionId = `${toolId}-${contentHash}`;

    const prevTool: Tool | undefined = await context.Tool.get(toolId);
    const prevVersion: ToolVersion | undefined =
      await context.ToolVersion.get(versionId);
    const isNewVersion = prevVersion === undefined;

    context.Tool.set({
      id: toolId,
      firstSeen: prevTool?.firstSeen ?? ts,
      lastSeen: ts,
      scanCount: (prevTool?.scanCount ?? 0) + 1,
      cleanCount:
        (prevTool?.cleanCount ?? 0) + (verdict === VERDICT_CLEAN ? 1 : 0),
      warnCount:
        (prevTool?.warnCount ?? 0) + (verdict === VERDICT_WARN ? 1 : 0),
      criticalCount:
        (prevTool?.criticalCount ?? 0) + (verdict === VERDICT_CRITICAL ? 1 : 0),
      latestVerdict: verdict,
      latestScore: score,
      latestContentHash: contentHash,
      latestAttestor: attestorId,
      versionCount: (prevTool?.versionCount ?? 0) + (isNewVersion ? 1 : 0),
    });

    context.ToolVersion.set({
      id: versionId,
      tool_id: toolId,
      contentHash,
      firstSeen: prevVersion?.firstSeen ?? ts,
      lastSeen: ts,
      scanCount: (prevVersion?.scanCount ?? 0) + 1,
      latestVerdict: verdict,
      latestScore: score,
    });

    const prevAttestor: Attestor | undefined =
      await context.Attestor.get(attestorId);
    const firstTimeOnTool =
      prevTool === undefined || prevTool.latestAttestor !== attestorId;
    context.Attestor.set({
      id: attestorId,
      pubKeyX: prevAttestor?.pubKeyX,
      pubKeyY: prevAttestor?.pubKeyY,
      metaURI: prevAttestor?.metaURI,
      registeredAt: prevAttestor?.registeredAt,
      scanCount: (prevAttestor?.scanCount ?? 0) + 1,
      toolsCovered: (prevAttestor?.toolsCovered ?? 0) + (firstTimeOnTool ? 1 : 0),
    });

    const scanRow: Scan = {
      id: `${event.transaction.hash}-${event.logIndex}`,
      tool_id: toolId,
      version_id: versionId,
      attestor_id: attestorId,
      contentHash,
      verdict,
      score,
      receiptHash: event.params.receiptHash,
      receiptURI: event.params.receiptURI,
      timestamp: ts,
      blockNumber: event.block.number,
      txHash: event.transaction.hash,
    };
    context.Scan.set(scanRow);
  },
);
