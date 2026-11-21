import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import cors from "cors";
import express, { type Request, type Response } from "express";
import multer from "multer";
import {
  buildCaseCsv,
  buildCaseHtmlReport,
  type CaseReport,
  computeCaseVerdict,
  type CorrelationItem,
  type EvidenceItem,
  type Indicator,
  inspectBinarySignals,
  isFakeIndicator,
  scanBinaryMetadata,
  slugify,
  utcNow,
} from "./lib/forensics.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const FRONTEND_DIR = [
  path.resolve(__dirname, "public"),
  path.resolve(__dirname, "..", "public"),
  path.resolve(process.cwd(), "public"),
].find((dir) => fs.existsSync(dir)) ?? path.resolve(process.cwd(), "public");

const casesStore = new Map<string, CaseReport>();

function saveCase(report: CaseReport): void {
  const slug = slugify(report.case_id);
  const { verdict, overall_risk_score } = computeCaseVerdict(report.indicators || []);
  report.verdict = verdict;
  report.overall_risk_score = overall_risk_score;
  report.updated_at = utcNow();
  casesStore.delete(slug);
  casesStore.set(slug, report);
}

function loadCase(slug: string): CaseReport | null {
  return casesStore.get(slugify(slug)) ?? null;
}

function seedBaselineCases(): void {
  const authenticCase: CaseReport = {
    case_id: "CASE-2026-0902",
    claim: "Field patrol bodycam clip & hardware-signed still frame from municipal inspection",
    created_at: "2026-11-18T14:22:10Z",
    updated_at: "2026-11-18T14:22:10Z",
    overall_risk_score: 0,
    verdict: "AUTHENTIC",
    pipeline_stages: [
      { name: "1. Evidence Intake", status: "completed", duration_ms: 14 },
      { name: "2. Modality Extraction", status: "completed", duration_ms: 42 },
      { name: "3. Fake & Anomaly Analysis", status: "completed", duration_ms: 118 },
      { name: "4. Cross-Modal Correlation", status: "completed", duration_ms: 23 },
      { name: "5. Verdict & Audit Synthesis", status: "completed", duration_ms: 9 },
    ],
    evidence: [
      {
        evidence_id: "EV-VID-01",
        filename: "patrol_cam_0902.mp4",
        media_type: "video",
        size_bytes: 24910336,
        sha256: "2b77d4109f3c8e51a604f18e2a94c7d8f03152a19d70b63e4a912c8f7d3a0418",
        md5: "7c910a84b2e31d990a14e22b4f8c601a",
        duration_sec: 16.0,
        metadata: {
          content_type: "video/mp4",
          bytes: 24910336,
          detected_magic: "ISO BMFF / MP4 (mp42)",
          extension_match: true,
          shannon_entropy: 7.4218,
          entropy_bins: [
            7.12, 7.38, 7.44, 7.41, 7.39, 7.45, 7.43, 7.4,
            7.42, 7.44, 7.41, 7.38, 7.43, 7.46, 7.41, 7.39,
            7.44, 7.42, 7.4, 7.43, 7.45, 7.41, 7.39, 7.42,
            7.44, 7.43, 7.41, 7.4, 7.42, 7.43, 7.39, 7.36,
          ],
          zero_byte_ratio: 0.0082,
          c2pa_present: true,
          exif_present: true,
          software_signatures: [],
          hex_preview:
            "0000: 00 00 00 18 66 74 79 70  6d 70 34 32 00 00 00 00  |....ftypmp42....|\n" +
            "0010: 6d 70 34 32 69 73 6f 6d  00 00 02 a4 6a 75 6d 62  |mp42isom....jumb|\n" +
            "0020: 63 32 70 61 00 00 00 1c  6a 75 6d 64 63 32 6d 61  |c2pa....jumdc2ma|",
        },
      },
      {
        evidence_id: "EV-IMG-02",
        filename: "site_still_0902.jpg",
        media_type: "image",
        size_bytes: 4128960,
        sha256: "8d12a6c40e9b3f7718d2e5c10a9b4e38f12c7a6904d81e2c5f9b7a103e84d261",
        md5: "44b89c120d1a8e4391a0f77b2e55c18d",
        duration_sec: 16.0,
        metadata: {
          content_type: "image/jpeg",
          bytes: 4128960,
          detected_magic: "JPEG / JFIF / Exif",
          extension_match: true,
          shannon_entropy: 7.5812,
          entropy_bins: [
            6.92, 7.54, 7.61, 7.59, 7.57, 7.62, 7.58, 7.6,
            7.59, 7.55, 7.61, 7.58, 7.57, 7.6, 7.59, 7.58,
            7.61, 7.56, 7.59, 7.6, 7.58, 7.57, 7.59, 7.61,
            7.58, 7.56, 7.6, 7.59, 7.57, 7.58, 7.55, 7.49,
          ],
          zero_byte_ratio: 0.0041,
          c2pa_present: true,
          exif_present: true,
          software_signatures: [],
          hex_preview:
            "0000: ff d8 ff e1 18 4a 45 78  69 66 00 00 4d 4d 00 2a  |.....JExif..MM.*|\n" +
            "0010: 00 00 00 08 00 0a 01 0f  00 02 00 00 00 06 53 6f  |..............So|\n" +
            "0020: 6e 79 00 00 01 10 00 02  49 4c 43 45 2d 37 4d 34  |ny......ILCE-7M4|",
        },
      },
    ],
    indicators: [
      {
        finding_id: "F-001",
        evidence_id: "EV-VID-01",
        modality: "video",
        location: "Full Bitstream Integrity",
        timestamp_sec: 2.0,
        bbox: { x: 0.22, y: 0.18, w: 0.56, h: 0.64 },
        signal_summary: "PROVENANCE VERIFIED: C2PA Content Credentials intact & clean bitstream (ISO BMFF / MP4)",
        calibrated_confidence: 0.04,
        fraud_label: "AUTHENTIC",
        disposition: "Confirmed Authentic",
        reviewer_note: "Hardware manifest signature validated against capture timestamp.",
      },
      {
        finding_id: "F-002",
        evidence_id: "EV-IMG-02",
        modality: "image",
        location: "EXIF & Sensor Noise Residual",
        timestamp_sec: 6.0,
        bbox: { x: 0.2, y: 0.16, w: 0.6, h: 0.66 },
        signal_summary: "CAMERA PROVENANCE CONSISTENT: Sony ILCE-7M4 EXIF intact with uniform PRNU noise floor",
        calibrated_confidence: 0.06,
        fraud_label: "AUTHENTIC",
        disposition: "Confirmed Authentic",
        reviewer_note: "Zero post-capture editing markers detected.",
      },
    ],
    correlations: [
      {
        correlation_id: "CORR-01",
        relation: "HARDWARE_PROVENANCE_ALIGNMENT",
        score: 0.98,
        summary: "Both submitted assets carry intact C2PA / hardware capture signatures with consistent timelines.",
      },
    ],
    audit_log: [
      {
        timestamp: "2026-11-18T14:22:10Z",
        action: "ANALYZE_CASE",
        detail: "Processed 2 evidence items; C2PA & EXIF provenance verified across video and still.",
      },
    ],
  };

  const deepfakeCase: CaseReport = {
    case_id: "CASE-2026-0814",
    claim: "Alleged CFO video call authorizing $480,000 urgent wire transfer",
    created_at: "2026-11-19T10:14:02Z",
    updated_at: "2026-11-19T10:14:02Z",
    overall_risk_score: 95,
    verdict: "FAKE",
    pipeline_stages: [
      { name: "1. Evidence Intake", status: "completed", duration_ms: 18 },
      { name: "2. Modality Extraction", status: "completed", duration_ms: 54 },
      { name: "3. Fake & Anomaly Analysis", status: "completed", duration_ms: 146 },
      { name: "4. Cross-Modal Correlation", status: "completed", duration_ms: 31 },
      { name: "5. Verdict & Audit Synthesis", status: "completed", duration_ms: 11 },
    ],
    evidence: [
      {
        evidence_id: "EV-VID-01",
        filename: "cfo_call_recording.mp4",
        media_type: "video",
        size_bytes: 18429104,
        sha256: "9f84c2a17b3e40d8912a6c55e10984f3b7c12a9e00412d88f31c66a9012e4b71",
        md5: "91e04b21c44a10f93b21a7c4d102b8e5",
        duration_sec: 16.0,
        metadata: {
          content_type: "video/mp4",
          bytes: 18429104,
          detected_magic: "ISO BMFF / MP4 (isom)",
          extension_match: true,
          shannon_entropy: 7.7104,
          entropy_bins: [
            6.85, 7.12, 7.21, 7.19, 7.25, 7.31, 7.28, 7.94,
            7.98, 7.91, 7.42, 7.35, 7.29, 7.33, 7.89, 7.96,
            7.92, 7.38, 7.34, 7.27, 7.3, 7.28, 7.31, 7.26,
            7.33, 7.29, 7.35, 7.41, 7.38, 7.32, 7.27, 7.19,
          ],
          zero_byte_ratio: 0.0114,
          c2pa_present: false,
          exif_present: false,
          software_signatures: ["FFmpeg / Lavf Muxer", "DeepFaceLab Swap Pipeline"],
          hex_preview:
            "0000: 00 00 00 20 66 74 79 70  69 73 6f 6d 00 00 02 00  |... ftypisom....|\n" +
            "0010: 69 73 6f 6d 69 73 6f 32  61 76 63 31 6d 70 34 31  |isomiso2avc1mp41|\n" +
            "0020: 00 00 00 4c 75 64 74 61  4c 61 76 66 36 30 2e 33  |...LudtaLavf60.3|",
        },
      },
      {
        evidence_id: "EV-AUD-02",
        filename: "cfo_voice_isolated.wav",
        media_type: "audio",
        size_bytes: 3072440,
        sha256: "4e11d8a93f20c77b15e84a90d312c88b71a04f92e63d518c29f04b77a12c3e90",
        md5: "32d48f9a10bc77e4512c09d1f44e88b2",
        duration_sec: 16.0,
        metadata: {
          content_type: "audio/wav",
          bytes: 3072440,
          detected_magic: "RIFF / WAVE Audio",
          extension_match: true,
          shannon_entropy: 7.482,
          entropy_bins: [
            6.45, 6.62, 6.71, 6.68, 6.74, 6.69, 6.72, 6.65,
            6.7, 6.68, 6.71, 6.66, 6.73, 7.88, 7.95, 7.91,
            7.89, 7.84, 6.75, 6.71, 6.68, 6.72, 6.69, 6.67,
            6.71, 6.68, 6.64, 6.69, 6.72, 6.68, 6.65, 6.61,
          ],
          zero_byte_ratio: 0.0235,
          c2pa_present: false,
          exif_present: false,
          software_signatures: ["ElevenLabs Voice Synthesis"],
          hex_preview:
            "0000: 52 49 46 46 28 e2 2e 00  57 41 56 45 66 6d 74 20  |RIFF(...WAVEfmt |\n" +
            "0010: 10 00 00 00 01 00 01 00  80 bb 00 00 00 77 01 00  |.............w..|\n" +
            "0020: 02 00 10 00 4c 49 53 54  45 6c 65 76 65 6e 4c 61  |....LISTElevenLa|",
        },
      },
    ],
    indicators: [
      {
        finding_id: "F-001",
        evidence_id: "EV-VID-01",
        modality: "video",
        location: "00:04.2 (Frames 120-168)",
        timestamp_sec: 4.2,
        bbox: { x: 0.34, y: 0.22, w: 0.32, h: 0.44 },
        signal_summary: "FAKE FACE-SWAP: Jawline blending seam & GAN texture flicker during head turn",
        calibrated_confidence: 0.94,
        fraud_label: "FAKE",
        disposition: "Confirmed Anomaly",
        reviewer_note: "Clear boundary warping around lower chin.",
      },
      {
        finding_id: "F-002",
        evidence_id: "EV-AUD-02",
        modality: "audio",
        location: "00:07.5 (7.2s - 8.9s)",
        timestamp_sec: 7.5,
        bbox: { x: 0.36, y: 0.26, w: 0.28, h: 0.38 },
        signal_summary: "FAKE VOICE CLONE: Neural vocoder harmonic cutoff above 7.6 kHz",
        calibrated_confidence: 0.95,
        fraud_label: "FAKE",
        disposition: "Confirmed Anomaly",
        reviewer_note: "Matches TTS splice on wire account digits.",
      },
      {
        finding_id: "F-003",
        evidence_id: "EV-VID-01",
        modality: "metadata",
        location: "Container Header (moov/udta)",
        timestamp_sec: 1.2,
        bbox: { x: 0.18, y: 0.14, w: 0.64, h: 0.72 },
        signal_summary: "CONTAINER RE-MUX: Re-encoded with FFmpeg/Lavf60.3 after original capture",
        calibrated_confidence: 0.76,
        fraud_label: "FAKE",
        disposition: "Unreviewed",
        reviewer_note: "",
      },
    ],
    correlations: [
      {
        correlation_id: "CORR-01",
        relation: "AUDIO_VIDEO_DEEPFAKE_MATCH",
        score: 0.96,
        summary: "Voice-clone splice at 00:07.5 aligns with facial reenactment & Lavf re-mux traces.",
      },
    ],
    audit_log: [
      {
        timestamp: "2026-11-19T10:14:02Z",
        action: "INIT_DEMO",
        detail: "Loaded baseline forensic deepfake case (2 evidence items, 3 indicators).",
      },
    ],
  };

  saveCase(authenticCase);
  saveCase(deepfakeCase);
}

seedBaselineCases();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024, files: 10 },
});

const app = express();
app.use(
  cors({
    origin: "*",
    credentials: false,
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["*"],
  }),
);
app.use(express.json());

if (fs.existsSync(FRONTEND_DIR)) {
  app.use("/static", express.static(FRONTEND_DIR));
}

app.get("/", (_req: Request, res: Response) => {
  const indexFile = path.join(FRONTEND_DIR, "index.html");
  if (!fs.existsSync(indexFile)) {
    res
      .status(404)
      .send(
        "<h2>public/index.html not found</h2><p>Place <code>index.html</code> inside the <code>public/</code> folder.</p>",
      );
    return;
  }
  res.sendFile(indexFile);
});

app.get("/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    service: "blueorchids-truthlens",
    timestamp: utcNow(),
    case_count: casesStore.size,
  });
});

app.get("/cases", (_req: Request, res: Response) => {
  const entries = Array.from(casesStore.entries()).reverse();
  const cases = entries.map(([slug, data]) => ({
    slug,
    case_id: data.case_id || slug,
    claim: data.claim || "",
    verdict: data.verdict,
    overall_risk_score: data.overall_risk_score,
    evidence_count: (data.evidence || []).length,
    indicator_count: (data.indicators || []).length,
    updated_at: data.updated_at,
  }));
  res.json({ cases });
});

app.get("/cases/:slug", (req: Request, res: Response) => {
  const slug = String(req.params.slug);
  const report = loadCase(slug);
  if (!report) {
    res.status(404).json({ detail: `Case '${slug}' not found` });
    return;
  }
  res.json(report);
});

app.delete("/cases/:slug", (req: Request, res: Response) => {
  const slug = slugify(String(req.params.slug));
  if (!casesStore.has(slug)) {
    res.status(404).json({ detail: `Case '${slug}' not found` });
    return;
  }
  casesStore.delete(slug);
  res.json({ deleted: slug });
});

app.post("/analyze", upload.array("files"), (req: Request, res: Response) => {
  const startMs = Date.now();
  const rawCaseId = typeof req.body?.case_id === "string" ? req.body.case_id : "";
  if (!rawCaseId.trim()) {
    res.status(422).json({ detail: "case_id is required" });
    return;
  }

  const claim = typeof req.body?.claim === "string" ? req.body.claim : "";
  const slug = slugify(rawCaseId);
  const uploadedFiles = (req.files as Express.Multer.File[] | undefined) || [];

  const evidenceItems: EvidenceItem[] = [];
  const indicators: Indicator[] = [];
  let findingCounter = 1;

  uploadedFiles.forEach((up, i) => {
    const idx = i + 1;
    const raw = up.buffer || Buffer.alloc(0);
    const sha256 = crypto.createHash("sha256").update(raw).digest("hex");
    const md5 = crypto.createHash("md5").update(raw).digest("hex");
    const safeName = path.basename(up.originalname || `upload_${idx}.bin`);
    const { modality, metadata } = scanBinaryMetadata(safeName, up.mimetype || "", raw);
    const evId = `EV-${modality.slice(0, 3).toUpperCase()}-${String(idx).padStart(2, "0")}`;

    evidenceItems.push({
      evidence_id: evId,
      filename: safeName,
      media_type: modality,
      size_bytes: raw.length,
      sha256,
      md5,
      duration_sec: 16.0,
      metadata,
    });

    const newInds = inspectBinarySignals(evId, safeName, modality, raw, findingCounter, metadata);
    indicators.push(...newInds);
    findingCounter += newInds.length;
  });

  if (evidenceItems.length === 0) {
    const claimBuf = Buffer.from(claim, "utf-8");
    const { metadata } = scanBinaryMetadata("claim_statement.txt", "text/plain", claimBuf);
    evidenceItems.push({
      evidence_id: "EV-CLAIM-01",
      filename: "claim_statement.txt",
      media_type: "metadata",
      size_bytes: claimBuf.length,
      sha256: crypto.createHash("sha256").update(claimBuf).digest("hex"),
      md5: crypto.createHash("md5").update(claimBuf).digest("hex"),
      duration_sec: 16.0,
      metadata,
    });
  }

  const fakeIndicators = indicators.filter(isFakeIndicator);
  const correlations: CorrelationItem[] = [];
  if (fakeIndicators.length >= 2) {
    const modalities = Array.from(new Set(fakeIndicators.map((i) => i.modality)));
    correlations.push({
      correlation_id: "CORR-01",
      relation: modalities.length > 1 ? "CROSS_MODAL_FRAUD_ALIGNMENT" : "MULTI_SIGNAL_TAMPER_CLUSTER",
      score: Math.min(0.99, Number((0.84 + fakeIndicators.length * 0.04).toFixed(2))),
      summary: `Correlated ${fakeIndicators.length} tampering/synthetic indicators across ${modalities.join(" + ")} evidence.`,
    });
  } else if (evidenceItems.length > 0 && fakeIndicators.length === 0) {
    correlations.push({
      correlation_id: "CORR-01",
      relation: "BASELINE_INTEGRITY_CONSISTENT",
      score: 0.92,
      summary: `All ${evidenceItems.length} submitted evidence item(s) passed magic-byte, signature, and entropy uniformity checks.`,
    });
  }

  const now = utcNow();
  const elapsed = Math.max(12, Date.now() - startMs);
  const { verdict, overall_risk_score } = computeCaseVerdict(indicators);

  const report: CaseReport = {
    case_id: slug,
    claim,
    created_at: now,
    updated_at: now,
    overall_risk_score,
    verdict,
    pipeline_stages: [
      { name: "1. Evidence Intake", status: "completed", duration_ms: Math.max(3, Math.round(elapsed * 0.15)) },
      { name: "2. Modality Extraction", status: "completed", duration_ms: Math.max(4, Math.round(elapsed * 0.25)) },
      { name: "3. Fake & Anomaly Analysis", status: "completed", duration_ms: Math.max(5, Math.round(elapsed * 0.4)) },
      { name: "4. Cross-Modal Correlation", status: "completed", duration_ms: Math.max(2, Math.round(elapsed * 0.12)) },
      { name: "5. Verdict & Audit Synthesis", status: "completed", duration_ms: Math.max(1, Math.round(elapsed * 0.08)) },
    ],
    evidence: evidenceItems,
    indicators,
    correlations,
    audit_log: [
      {
        timestamp: now,
        action: "ANALYZE_CASE",
        detail: `Processed ${evidenceItems.length} evidence item(s); verdict=${verdict} (${overall_risk_score}% risk); ${indicators.length} indicator(s).`,
      },
    ],
  };

  saveCase(report);
  res.json(report);
});

app.patch("/cases/:slug/indicators/:finding_id", (req: Request, res: Response) => {
  const slug = String(req.params.slug);
  const findingId = String(req.params.finding_id);
  const report = loadCase(slug);
  if (!report) {
    res.status(404).json({ detail: `Case '${slug}' not found` });
    return;
  }

  const disposition = typeof req.body?.disposition === "string" ? req.body.disposition : "";
  const reviewerNote = typeof req.body?.reviewer_note === "string" ? req.body.reviewer_note : "";

  if (!disposition) {
    res.status(422).json({ detail: "disposition is required" });
    return;
  }

  let matched = false;
  for (const ind of report.indicators || []) {
    if (ind.finding_id === findingId) {
      ind.disposition = disposition;
      ind.reviewer_note = reviewerNote;
      matched = true;
      break;
    }
  }

  if (!matched) {
    res.status(404).json({ detail: `Finding '${findingId}' not found in case '${slug}'` });
    return;
  }

  report.audit_log = report.audit_log || [];
  report.audit_log.push({
    timestamp: utcNow(),
    action: "PATCH_DISPOSITION",
    detail: `${findingId} updated to '${disposition}' (${reviewerNote || "no note"})`,
  });
  saveCase(report);
  res.json(report);
});

app.get("/cases/:slug/report.html", (req: Request, res: Response) => {
  const slug = String(req.params.slug);
  const report = loadCase(slug);
  if (!report) {
    res.status(404).json({ detail: `Case '${slug}' not found` });
    return;
  }
  res.type("html").send(buildCaseHtmlReport(report, slug));
});

app.get("/cases/:slug/report.json", (req: Request, res: Response) => {
  const slug = String(req.params.slug);
  const report = loadCase(slug);
  if (!report) {
    res.status(404).json({ detail: `Case '${slug}' not found` });
    return;
  }
  res.setHeader("Content-Disposition", `attachment; filename="${slugify(report.case_id)}-forensic-report.json"`);
  res.json(report);
});

app.get("/cases/:slug/report.csv", (req: Request, res: Response) => {
  const slug = String(req.params.slug);
  const report = loadCase(slug);
  if (!report) {
    res.status(404).json({ detail: `Case '${slug}' not found` });
    return;
  }
  res.setHeader("Content-Disposition", `attachment; filename="${slugify(report.case_id)}-findings.csv"`);
  res.type("text/csv").send(buildCaseCsv(report));
});

const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`TruthLens server listening on http://0.0.0.0:${PORT}`);
});
