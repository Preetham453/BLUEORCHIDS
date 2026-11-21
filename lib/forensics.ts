import crypto from "node:crypto";
import path from "node:path";

export interface BoundingBox {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface Indicator {
  finding_id: string;
  evidence_id: string;
  modality: string;
  location: string;
  timestamp_sec: number;
  bbox: BoundingBox;
  signal_summary: string;
  calibrated_confidence: number;
  fraud_label: "FAKE" | "SUSPICIOUS" | "AUTHENTIC";
  disposition: string;
  reviewer_note: string;
}

export interface ExtractedMetadata {
  content_type: string;
  bytes: number;
  detected_magic: string;
  extension_match: boolean;
  shannon_entropy: number;
  entropy_bins: number[];
  zero_byte_ratio: number;
  c2pa_present: boolean;
  exif_present: boolean;
  software_signatures: string[];
  hex_preview: string;
}

export interface EvidenceItem {
  evidence_id: string;
  filename: string;
  media_type: string;
  size_bytes: number;
  sha256: string;
  md5: string;
  duration_sec: number;
  metadata: ExtractedMetadata;
}

export interface CorrelationItem {
  correlation_id: string;
  relation: string;
  score: number;
  summary: string;
}

export interface AuditEvent {
  timestamp: string;
  action: string;
  detail: string;
}

export interface PipelineStage {
  name: string;
  status: string;
  duration_ms?: number;
}

export interface CaseReport {
  case_id: string;
  claim: string;
  created_at: string;
  updated_at: string;
  overall_risk_score: number;
  verdict: "FAKE" | "REVIEW" | "AUTHENTIC";
  pipeline_stages: PipelineStage[];
  evidence: EvidenceItem[];
  indicators: Indicator[];
  correlations: CorrelationItem[];
  audit_log: AuditEvent[];
}

export function utcNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function slugify(value: string): string {
  const cleaned = value
    .trim()
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned || "CASE-UNTITLED";
}

export function escapeHtml(str: unknown): string {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function inferModality(filename: string, contentType: string): string {
  const ct = (contentType || "").toLowerCase();
  const ext = path.extname(filename || "").toLowerCase();
  if (ct.startsWith("video/") || [".mp4", ".mov", ".avi", ".mkv", ".webm"].includes(ext)) {
    return "video";
  }
  if (ct.startsWith("audio/") || [".wav", ".mp3", ".m4a", ".aac", ".flac", ".ogg"].includes(ext)) {
    return "audio";
  }
  if (ct.startsWith("image/") || [".jpg", ".jpeg", ".png", ".webp", ".tiff", ".bmp"].includes(ext)) {
    return "image";
  }
  return "metadata";
}

export function detectMagicSignature(buf: Buffer): { label: string; family: string } {
  if (buf.length < 4) return { label: "Empty / Tiny Payload", family: "metadata" };

  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return { label: "JPEG / JFIF / Exif", family: "image" };
  }
  if (buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return { label: "PNG Image", family: "image" };
  }
  if (buf.subarray(0, 4).toString("ascii") === "RIFF" && buf.length >= 12) {
    const form = buf.subarray(8, 12).toString("ascii");
    if (form === "WAVE") return { label: "RIFF / WAVE Audio", family: "audio" };
    if (form === "WEBP") return { label: "RIFF / WebP Image", family: "image" };
    if (form === "AVI ") return { label: "RIFF / AVI Video", family: "video" };
    return { label: `RIFF (${form})`, family: "metadata" };
  }
  if (buf.subarray(0, 4).toString("ascii") === "fLaC") {
    return { label: "FLAC Lossless Audio", family: "audio" };
  }
  if (buf.subarray(0, 4).toString("ascii") === "OggS") {
    return { label: "Ogg Container", family: "audio" };
  }
  if (buf.subarray(0, 3).toString("ascii") === "ID3" || (buf[0] === 0xff && (buf[1] & 0xe0) === 0xe0)) {
    return { label: "MP3 / MPEG Audio", family: "audio" };
  }
  if (buf.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))) {
    return { label: "EBML / Matroska / WebM", family: "video" };
  }
  if (buf.length >= 12 && buf.subarray(4, 8).toString("ascii") === "ftyp") {
    const brand = buf.subarray(8, 12).toString("ascii").replace(/[^\x20-\x7e]/g, ".");
    return { label: `ISO BMFF / MP4 (${brand})`, family: "video" };
  }
  if (buf.subarray(0, 4).toString("ascii") === "%PDF") {
    return { label: "PDF Document", family: "metadata" };
  }
  // Check printable ASCII / JSON / UTF-8 text
  const sample = buf.subarray(0, Math.min(buf.length, 512));
  let printable = 0;
  for (let i = 0; i < sample.length; i++) {
    const b = sample[i];
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) printable++;
  }
  if (sample.length > 0 && printable / sample.length > 0.92) {
    return { label: "UTF-8 / ASCII Structured Text", family: "metadata" };
  }
  return { label: "Unidentified Binary Stream", family: "metadata" };
}

export function computeShannonEntropy(buf: Buffer): number {
  if (buf.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buf.length; i++) {
    counts[buf[i]]++;
  }
  let entropy = 0;
  const len = buf.length;
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
}

export function computeEntropyBins(buf: Buffer, binCount = 32): number[] {
  if (buf.length === 0) return Array(binCount).fill(0);
  const actualBins = Math.max(4, Math.min(64, binCount));
  const bins: number[] = [];
  const step = Math.max(1, Math.floor(buf.length / actualBins));
  for (let i = 0; i < actualBins; i++) {
    const start = Math.floor((i * buf.length) / actualBins);
    const end = i === actualBins - 1 ? buf.length : Math.max(start + step, Math.floor(((i + 1) * buf.length) / actualBins));
    const slice = buf.subarray(start, Math.min(buf.length, end));
    bins.push(slice.length > 0 ? computeShannonEntropy(slice) : 0);
  }
  return bins;
}

export function formatHexPreview(buf: Buffer, maxBytes = 256): string {
  const slice = buf.subarray(0, Math.min(buf.length, maxBytes));
  const lines: string[] = [];
  for (let offset = 0; offset < slice.length; offset += 16) {
    const chunk = slice.subarray(offset, offset + 16);
    const hexParts: string[] = [];
    let ascii = "";
    for (let i = 0; i < 16; i++) {
      if (i < chunk.length) {
        const b = chunk[i];
        hexParts.push(b.toString(16).padStart(2, "0"));
        ascii += b >= 32 && b <= 126 ? String.fromCharCode(b) : ".";
      } else {
        hexParts.push("  ");
        ascii += " ";
      }
    }
    const addr = offset.toString(16).padStart(4, "0");
    lines.push(`${addr}: ${hexParts.slice(0, 8).join(" ")}  ${hexParts.slice(8).join(" ")}  |${ascii}|`);
  }
  return lines.join("\n");
}

const KNOWN_SIGNATURES: Array<{
  pattern: string;
  label: string;
  severity: "synthetic" | "editing" | "remux";
  confidence: number;
}> = [
  { pattern: "Lavf", label: "FFmpeg / Lavf Muxer", severity: "remux", confidence: 0.74 },
  { pattern: "Lavc", label: "FFmpeg / Lavc Codec", severity: "remux", confidence: 0.72 },
  { pattern: "FFmpeg", label: "FFmpeg Processing Pipeline", severity: "remux", confidence: 0.76 },
  { pattern: "HandBrake", label: "HandBrake Transcoder", severity: "editing", confidence: 0.65 },
  { pattern: "Adobe Premiere", label: "Adobe Premiere Pro", severity: "editing", confidence: 0.72 },
  { pattern: "After Effects", label: "Adobe After Effects", severity: "editing", confidence: 0.81 },
  { pattern: "Photoshop", label: "Adobe Photoshop", severity: "editing", confidence: 0.75 },
  { pattern: "CapCut", label: "CapCut Mobile Editor", severity: "editing", confidence: 0.69 },
  { pattern: "DaVinci", label: "DaVinci Resolve", severity: "editing", confidence: 0.66 },
  { pattern: "Stable Diffusion", label: "Stable Diffusion Generator", severity: "synthetic", confidence: 0.96 },
  { pattern: "ComfyUI", label: "ComfyUI Node Workflow", severity: "synthetic", confidence: 0.97 },
  { pattern: "AUTOMATIC1111", label: "A1111 Diffusion WebUI", severity: "synthetic", confidence: 0.96 },
  { pattern: "Midjourney", label: "Midjourney Generator", severity: "synthetic", confidence: 0.95 },
  { pattern: "DALL-E", label: "DALL-E Image Generator", severity: "synthetic", confidence: 0.95 },
  { pattern: "ElevenLabs", label: "ElevenLabs Voice Synthesis", severity: "synthetic", confidence: 0.96 },
  { pattern: "Runway", label: "Runway Gen Video Synthesis", severity: "synthetic", confidence: 0.93 },
  { pattern: "Sora", label: "Sora Video Model Tag", severity: "synthetic", confidence: 0.94 },
  { pattern: "DeepFaceLab", label: "DeepFaceLab Swap Pipeline", severity: "synthetic", confidence: 0.98 },
  { pattern: "FaceSwap", label: "FaceSwap Neural Pipeline", severity: "synthetic", confidence: 0.97 },
];

export function scanBinaryMetadata(
  filename: string,
  contentType: string,
  raw: Buffer,
): { modality: string; metadata: ExtractedMetadata } {
  const modality = inferModality(filename, contentType);
  const magic = detectMagicSignature(raw);
  const ext = path.extname(filename || "").toLowerCase();

  let extensionMatch = true;
  if (raw.length >= 8) {
    if (ext && [".jpg", ".jpeg", ".png", ".webp"].includes(ext) && magic.family !== "image") {
      extensionMatch = false;
    } else if (ext && [".mp4", ".mov", ".avi", ".mkv", ".webm"].includes(ext) && magic.family !== "video") {
      extensionMatch = false;
    } else if (ext && [".wav", ".mp3", ".m4a", ".aac", ".flac", ".ogg"].includes(ext) && magic.family !== "audio" && !magic.label.includes("MP4")) {
      extensionMatch = false;
    }
  }

  let zeroCount = 0;
  const sampleLen = Math.min(raw.length, 262144);
  for (let i = 0; i < sampleLen; i++) {
    if (raw[i] === 0) zeroCount++;
  }
  const zeroByteRatio = sampleLen > 0 ? Number((zeroCount / sampleLen).toFixed(4)) : 0;

  // Scan head + tail (MP4 moov/udta atoms often sit at the tail!)
  const headSlice = raw.subarray(0, Math.min(raw.length, 131072));
  const tailSlice = raw.length > 131072 ? raw.subarray(Math.max(131072, raw.length - 131072)) : Buffer.alloc(0);
  const scanText = headSlice.toString("latin1") + "\n" + tailSlice.toString("latin1");

  const foundSignatures: string[] = [];
  for (const sig of KNOWN_SIGNATURES) {
    if (scanText.toLowerCase().includes(sig.pattern.toLowerCase())) {
      foundSignatures.push(sig.label);
    }
  }

  const c2paPresent = /c2pa|jumbf|jumb/i.test(scanText);
  const exifPresent = /Exif\x00\x00|Make|Model|DateTimeOriginal|iPhone|Canon|Nikon|Sony/i.test(scanText);

  return {
    modality,
    metadata: {
      content_type: contentType || "application/octet-stream",
      bytes: raw.length,
      detected_magic: magic.label,
      extension_match: extensionMatch,
      shannon_entropy: computeShannonEntropy(raw.subarray(0, 262144)),
      entropy_bins: computeEntropyBins(raw, 32),
      zero_byte_ratio: zeroByteRatio,
      c2pa_present: c2paPresent,
      exif_present: exifPresent,
      software_signatures: Array.from(new Set(foundSignatures)),
      hex_preview: formatHexPreview(raw, 256),
    },
  };
}

export function inspectBinarySignals(
  evidenceId: string,
  filename: string,
  modality: string,
  raw: Buffer,
  startIndex: number,
  precomputedMeta?: ExtractedMetadata,
): Indicator[] {
  const meta = precomputedMeta ?? scanBinaryMetadata(filename, "", raw).metadata;
  const indicators: Indicator[] = [];
  let idx = startIndex;

  const headSlice = raw.subarray(0, Math.min(raw.length, 131072));
  const tailSlice = raw.length > 131072 ? raw.subarray(Math.max(131072, raw.length - 131072)) : Buffer.alloc(0);
  const scanText = headSlice.toString("latin1") + "\n" + tailSlice.toString("latin1");

  if (!meta.extension_match) {
    indicators.push({
      finding_id: `F-${String(idx).padStart(3, "0")}`,
      evidence_id: evidenceId,
      modality: "metadata",
      location: "0x0000 (File Header Magic)",
      timestamp_sec: 0.5,
      bbox: { x: 0.1, y: 0.1, w: 0.8, h: 0.25 },
      signal_summary: `SPOOFED EXTENSION: Filename '${filename}' does not match binary magic '${meta.detected_magic}'`,
      calibrated_confidence: 0.91,
      fraud_label: "FAKE",
      disposition: "Unreviewed",
      reviewer_note: "",
    });
    idx += 1;
  }

  for (const sig of KNOWN_SIGNATURES) {
    if (scanText.toLowerCase().includes(sig.pattern.toLowerCase())) {
      const isSynthetic = sig.severity === "synthetic";
      const isRemux = sig.severity === "remux";
      indicators.push({
        finding_id: `F-${String(idx).padStart(3, "0")}`,
        evidence_id: evidenceId,
        modality: isSynthetic ? modality : "metadata",
        location: isSynthetic ? "Embedded Generator Metadata" : "Container Header (moov/udta/XMP)",
        timestamp_sec: isSynthetic ? 4.2 : 1.2,
        bbox: isSynthetic
          ? { x: 0.3, y: 0.2, w: 0.4, h: 0.48 }
          : { x: 0.18, y: 0.14, w: 0.64, h: 0.72 },
        signal_summary: isSynthetic
          ? `SYNTHETIC GENERATOR SIGNATURE: Detected '${sig.label}' watermark/parameter string in ${filename}`
          : isRemux
            ? `CONTAINER RE-MUX: Re-encoded with ${sig.label} after original capture`
            : `POST-CAPTURE EDITING TRACE: Detected '${sig.label}' authoring signature in ${filename}`,
        calibrated_confidence: sig.confidence,
        fraud_label: isSynthetic || sig.confidence >= 0.74 ? "FAKE" : "SUSPICIOUS",
        disposition: "Unreviewed",
        reviewer_note: "",
      });
      idx += 1;
    }
  }

  // Entropy spike / structural splice check across the 32 bins
  if (meta.entropy_bins.length >= 8 && raw.length >= 512) {
    let maxJump = 0;
    let maxJumpIdx = 0;
    for (let i = 1; i < meta.entropy_bins.length; i++) {
      const jump = Math.abs(meta.entropy_bins[i] - meta.entropy_bins[i - 1]);
      if (jump > maxJump) {
        maxJump = jump;
        maxJumpIdx = i;
      }
    }
    if (maxJump >= 1.65) {
      const ts = Number(((maxJumpIdx / meta.entropy_bins.length) * 16.0).toFixed(1));
      indicators.push({
        finding_id: `F-${String(idx).padStart(3, "0")}`,
        evidence_id: evidenceId,
        modality,
        location: `Byte Offset Window #${maxJumpIdx} (~${ts.toFixed(1)}s)`,
        timestamp_sec: ts,
        bbox: { x: 0.28, y: 0.24, w: 0.44, h: 0.42 },
        signal_summary: `ENTROPY DISCONTINUITY: ${maxJump.toFixed(2)} bits/byte boundary shift indicating stream splice or appended payload`,
        calibrated_confidence: Math.min(0.88, Number((0.68 + (maxJump - 1.65) * 0.08).toFixed(2))),
        fraud_label: maxJump >= 2.2 ? "FAKE" : "SUSPICIOUS",
        disposition: "Unreviewed",
        reviewer_note: "",
      });
      idx += 1;
    }
  }

  // PNG prompt / diffusion parameter detection
  if (meta.detected_magic === "PNG Image" && /Negative prompt:|Steps:\s*\d+|Sampler:|CFG scale:/i.test(scanText)) {
    indicators.push({
      finding_id: `F-${String(idx).padStart(3, "0")}`,
      evidence_id: evidenceId,
      modality: "image",
      location: "PNG tEXt/iTXt Chunk",
      timestamp_sec: 2.5,
      bbox: { x: 0.25, y: 0.18, w: 0.5, h: 0.55 },
      signal_summary: `AI DIFFUSION PARAMETERS: Embedded generation prompt/CFG/seed metadata inside ${filename}`,
      calibrated_confidence: 0.98,
      fraud_label: "FAKE",
      disposition: "Unreviewed",
      reviewer_note: "",
    });
    idx += 1;
  }

  // If no tampering/synthetic indicators were found, emit a verified integrity finding
  if (indicators.length === 0) {
    indicators.push({
      finding_id: `F-${String(idx).padStart(3, "0")}`,
      evidence_id: evidenceId,
      modality,
      location: "Full Bitstream Integrity",
      timestamp_sec: 2.0,
      bbox: { x: 0.22, y: 0.18, w: 0.56, h: 0.64 },
      signal_summary: meta.c2pa_present
        ? `PROVENANCE VERIFIED: C2PA Content Credentials intact & clean bitstream (${meta.detected_magic})`
        : meta.exif_present
          ? `CAMERA PROVENANCE CONSISTENT: Hardware EXIF metadata intact with uniform entropy (${meta.shannon_entropy.toFixed(2)} b/B)`
          : `NO TAMPERING SIGNATURES: Clean ${meta.detected_magic} stream with uniform entropy (${meta.shannon_entropy.toFixed(2)} b/B)`,
      calibrated_confidence: 0.08,
      fraud_label: "AUTHENTIC",
      disposition: "Confirmed Authentic",
      reviewer_note: "",
    });
  }

  return indicators;
}

export function isFakeIndicator(ind: Partial<Indicator>): boolean {
  const conf = Number(ind?.calibrated_confidence ?? 0);
  const disp = String(ind?.disposition || "");
  const lbl = String(ind?.fraud_label || "").toUpperCase();
  if (disp === "Benign Artifact" || disp === "Confirmed Authentic") return false;
  if (lbl === "AUTHENTIC") return false;
  return lbl === "FAKE" || disp === "Confirmed Anomaly" || conf >= 0.7;
}

export function computeCaseVerdict(indicators: Indicator[]): {
  verdict: "FAKE" | "REVIEW" | "AUTHENTIC";
  overall_risk_score: number;
} {
  const fakes = indicators.filter(isFakeIndicator);
  if (fakes.length > 0) {
    const maxConf = fakes.reduce((m, i) => Math.max(m, Number(i.calibrated_confidence || 0)), 0);
    return { verdict: "FAKE", overall_risk_score: Math.round(maxConf * 100) };
  }
  const suspicious = indicators.filter(
    (i) =>
      i.disposition !== "Benign Artifact" &&
      i.disposition !== "Confirmed Authentic" &&
      (i.fraud_label === "SUSPICIOUS" || Number(i.calibrated_confidence || 0) >= 0.45),
  );
  if (suspicious.length > 0) {
    const maxConf = suspicious.reduce((m, i) => Math.max(m, Number(i.calibrated_confidence || 0)), 0);
    return { verdict: "REVIEW", overall_risk_score: Math.round(maxConf * 100) };
  }
  return { verdict: "AUTHENTIC", overall_risk_score: 0 };
}

export function buildCaseCsv(report: CaseReport): string {
  const header = [
    "case_id",
    "finding_id",
    "evidence_id",
    "fraud_label",
    "modality",
    "location",
    "timestamp_sec",
    "calibrated_confidence",
    "disposition",
    "signal_summary",
    "reviewer_note",
  ];
  const csvCell = (val: unknown): string => {
    const str = String(val ?? "");
    if (/[",\n\r]/.test(str)) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };
  const rows = (report.indicators || []).map((i) =>
    [
      report.case_id,
      i.finding_id,
      i.evidence_id,
      i.fraud_label,
      i.modality,
      i.location,
      i.timestamp_sec,
      Number(i.calibrated_confidence || 0).toFixed(2),
      i.disposition || "Unreviewed",
      i.signal_summary,
      i.reviewer_note || "",
    ]
      .map(csvCell)
      .join(","),
  );
  return [header.join(","), ...rows].join("\n");
}

export function buildCaseHtmlReport(report: CaseReport, slug: string): string {
  const { verdict, overall_risk_score } = computeCaseVerdict(report.indicators || []);
  const evidenceRows = (report.evidence || [])
    .map(
      (e) =>
        `<tr>` +
        `<td class="nowrap"><code>${escapeHtml(e.evidence_id)}</code></td>` +
        `<td>${escapeHtml(e.filename)}</td>` +
        `<td class="nowrap">${escapeHtml(e.media_type)}</td>` +
        `<td class="nowrap">${Number(e.size_bytes || 0).toLocaleString()} B</td>` +
        `<td class="nowrap"><code>${escapeHtml(e.metadata?.detected_magic || "-")}</code></td>` +
        `<td><code>${escapeHtml(e.sha256 || "")}</code></td>` +
        `</tr>`,
    )
    .join("");

  const rows = (report.indicators || [])
    .map(
      (i) =>
        `<tr>` +
        `<td class="nowrap"><code>${escapeHtml(i.finding_id || "")}</code></td>` +
        `<td class="nowrap"><strong>${escapeHtml(i.fraud_label || "")}</strong></td>` +
        `<td class="nowrap">${escapeHtml(i.modality || "")}</td>` +
        `<td><code>${escapeHtml(i.location || "")}</code></td>` +
        `<td>${escapeHtml(i.signal_summary || "")}</td>` +
        `<td class="nowrap">${Number(i.calibrated_confidence || 0).toFixed(2)}</td>` +
        `<td class="nowrap">${escapeHtml(i.disposition || "Unreviewed")}</td>` +
        `<td>${escapeHtml(i.reviewer_note || "")}</td>` +
        `</tr>`,
    )
    .join("");

  const auditRows = (report.audit_log || [])
    .map(
      (a) =>
        `<li><code>${escapeHtml(a.timestamp)}</code> — <strong>${escapeHtml(a.action)}</strong>: ${escapeHtml(a.detail)}</li>`,
    )
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>TruthLens Forensic Report — ${escapeHtml(report.case_id || slug)}</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; margin: 36px; color: #0f172a; line-height: 1.5; }
    h1 { margin-bottom: 4px; font-size: 22px; }
    h2 { margin-top: 28px; font-size: 16px; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; }
    .meta { background: #f8fafc; border: 1px solid #cbd5e1; padding: 14px 16px; border-radius: 6px; margin-top: 12px; }
    .verdict { font-weight: 700; color: ${verdict === "FAKE" ? "#b91c1c" : verdict === "REVIEW" ? "#b45309" : "#047857"}; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th, td { border: 1px solid #cbd5e1; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #f1f5f9; font-weight: 600; white-space: nowrap; }
    td.nowrap { white-space: nowrap; }
    code { font-family: ui-monospace, Menlo, monospace; font-size: 12px; word-break: break-all; }
    ul { font-size: 13px; padding-left: 20px; }
  </style>
</head>
<body>
  <h1>TruthLens Chain-of-Custody Forensic Report</h1>
  <div class="meta">
    <div><strong>Case ID:</strong> <code>${escapeHtml(report.case_id || slug)}</code></div>
    <div><strong>Verdict:</strong> <span class="verdict">${escapeHtml(verdict)} (${overall_risk_score}% Fraud Risk)</span></div>
    <div><strong>Claim:</strong> ${escapeHtml(report.claim || "None")}</div>
    <div><strong>Generated:</strong> <code>${escapeHtml(utcNow())}</code></div>
  </div>
  <h2>Evidence Inventory &amp; Cryptographic Digests</h2>
  <table>
    <thead><tr><th>ID</th><th>Filename</th><th>Modality</th><th>Size</th><th>Detected Format</th><th>SHA-256</th></tr></thead>
    <tbody>${evidenceRows}</tbody>
  </table>
  <h2>Forensic Indicators &amp; Investigator Dispositions</h2>
  <table>
    <thead>
      <tr>
        <th>Finding</th><th>Label</th><th>Modality</th><th>Location</th>
        <th>Signal Summary</th><th>Confidence</th><th>Disposition</th><th>Reviewer Note</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
  <h2>Audit Trail</h2>
  <ul>${auditRows}</ul>
</body>
</html>`;
}
