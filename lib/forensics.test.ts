import assert from "node:assert/strict";
import test from "node:test";
import {
  buildCaseCsv,
  buildCaseHtmlReport,
  computeCaseVerdict,
  computeEntropyBins,
  computeShannonEntropy,
  detectMagicSignature,
  inferModality,
  inspectBinarySignals,
  scanBinaryMetadata,
  slugify,
} from "./forensics";

test("slugify normalizes whitespace and special characters", () => {
  assert.equal(slugify("  CASE 2026 / 01 "), "CASE-2026-01");
  assert.equal(slugify("   "), "CASE-UNTITLED");
});

test("inferModality classifies video, audio, image, and metadata extensions", () => {
  assert.equal(inferModality("call.mp4", ""), "video");
  assert.equal(inferModality("voice.wav", "audio/wav"), "audio");
  assert.equal(inferModality("photo.png", ""), "image");
  assert.equal(inferModality("manifest.json", "application/json"), "metadata");
});

test("detectMagicSignature identifies PNG, JPEG, MP4 ftyp, and WAVE headers", () => {
  const pngHeader = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]);
  assert.equal(detectMagicSignature(pngHeader).label, "PNG Image");

  const jpgHeader = Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x00, 0x10]);
  assert.equal(detectMagicSignature(jpgHeader).label, "JPEG / JFIF / Exif");

  const mp4Header = Buffer.from([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d]);
  assert.equal(detectMagicSignature(mp4Header).label, "ISO BMFF / MP4 (isom)");
});

test("scanBinaryMetadata flags extension mismatch spoofing", () => {
  const textPayload = Buffer.from("This is actually plain text pretending to be an MP4", "utf-8");
  const { metadata } = scanBinaryMetadata("spoofed_video.mp4", "video/mp4", textPayload);
  assert.equal(metadata.extension_match, false);

  const inds = inspectBinarySignals("EV-VID-01", "spoofed_video.mp4", "video", textPayload, 1, metadata);
  assert.equal(inds.some((i) => i.signal_summary.includes("SPOOFED EXTENSION")), true);
  assert.equal(computeCaseVerdict(inds).verdict, "FAKE");
});

test("inspectBinarySignals detects FFmpeg/Lavf and AI diffusion parameters", () => {
  const pngPrefix = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const promptChunk = Buffer.from("tEXtparameters\x00portrait, Steps: 30, Sampler: Euler a, CFG scale: 7, ComfyUI", "utf-8");
  const payload = Buffer.concat([pngPrefix, promptChunk]);
  const { metadata } = scanBinaryMetadata("ai_portrait.png", "image/png", payload);
  const inds = inspectBinarySignals("EV-IMG-01", "ai_portrait.png", "image", payload, 1, metadata);

  assert.equal(metadata.extension_match, true);
  assert.equal(metadata.software_signatures.includes("ComfyUI Node Workflow"), true);
  assert.equal(inds.some((i) => i.fraud_label === "FAKE"), true);
  assert.equal(computeCaseVerdict(inds).verdict, "FAKE");
});

test("clean JPEG with Exif returns AUTHENTIC verdict", () => {
  const cleanJpeg = Buffer.concat([
    Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x00, 0x20]),
    Buffer.from("Exif\x00\x00Canon EOS R5 DateTimeOriginal 2026:11:18", "utf-8"),
    Buffer.alloc(256, 0x42),
  ]);
  const { metadata } = scanBinaryMetadata("camera_original.jpg", "image/jpeg", cleanJpeg);
  const inds = inspectBinarySignals("EV-IMG-01", "camera_original.jpg", "image", cleanJpeg, 1, metadata);

  assert.equal(metadata.extension_match, true);
  assert.equal(metadata.exif_present, true);
  assert.equal(inds.length, 1);
  assert.equal(inds[0].fraud_label, "AUTHENTIC");
  assert.equal(computeCaseVerdict(inds).verdict, "AUTHENTIC");
  assert.equal(computeCaseVerdict(inds).overall_risk_score, 0);
});

test("entropy calculation and binning return expected bounds", () => {
  const uniform = Buffer.alloc(1024, 0x00);
  assert.equal(computeShannonEntropy(uniform), 0);

  const varied = Buffer.from(Array.from({ length: 1024 }, (_, i) => i % 256));
  assert.equal(computeShannonEntropy(varied), 8);

  const bins = computeEntropyBins(varied, 16);
  assert.equal(bins.length, 16);
  assert.equal(bins.every((b) => b >= 0 && b <= 8), true);
});

test("CSV and HTML exports escape fields cleanly", () => {
  const report = {
    case_id: "CASE-CSV-01",
    claim: "Check <script>alert(1)</script>",
    created_at: "2026-11-20T00:00:00Z",
    updated_at: "2026-11-20T00:00:00Z",
    overall_risk_score: 94,
    verdict: "FAKE" as const,
    pipeline_stages: [],
    evidence: [],
    indicators: [
      {
        finding_id: "F-001",
        evidence_id: "EV-01",
        modality: "video",
        location: "00:04.2",
        timestamp_sec: 4.2,
        bbox: { x: 0.3, y: 0.2, w: 0.3, h: 0.4 },
        signal_summary: 'Quote "test", comma',
        calibrated_confidence: 0.94,
        fraud_label: "FAKE" as const,
        disposition: "Confirmed Anomaly",
        reviewer_note: "",
      },
    ],
    correlations: [],
    audit_log: [],
  };
  const csv = buildCaseCsv(report);
  assert.equal(csv.includes('"Quote ""test"", comma"'), true);

  const html = buildCaseHtmlReport(report, "CASE-CSV-01");
  assert.equal(html.includes("<script>"), false);
  assert.equal(html.includes("&lt;script&gt;"), true);
});
