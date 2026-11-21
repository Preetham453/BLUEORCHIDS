import {
  drawTrackCanvas,
  formatSec,
  isFakeIndicator,
  renderEntropyCanvas,
  renderViewportCanvas,
} from "./visualizers.js";

let currentReport = null;
let isPlaying = false;
let isMuted = false;
let playbackRate = 1.0;
let playheadSec = 0;
let mediaDurationSec = 16.0;
let lastFrameTs = null;
let rafId = null;

let activeViewportTab = "visual"; // "visual" | "entropy" | "hex"
let activeFilterMode = "normal"; // "normal" | "residual" | "heatmap"
let hoverPos = null;
let hoverBinIdx = null;
let selectedEvidenceId = "";
let pendingFiles = [];

let audioCtx = null;
let synthGain = null;
let synthOsc1 = null;
let synthOsc2 = null;
let analyserNode = null;
let liveFrequencyBins = null;
let uploadedVideoUrl = null;
let uploadedAudioUrl = null;
let uploadedImageEl = null;

const STAGES = [
  "1. Evidence Intake",
  "2. Modality Extraction",
  "3. Fake & Anomaly Analysis",
  "4. Cross-Modal Correlation",
  "5. Verdict & Audit Synthesis",
];

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatBytes(bytes) {
  const n = Number(bytes || 0);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function parseTimestampSec(ind, idx = 0, total = 1) {
  if (typeof ind.timestamp_sec === "number" && !Number.isNaN(ind.timestamp_sec)) return ind.timestamp_sec;
  const loc = String(ind.location || "");
  const m = loc.match(/(\d+):(\d+(?:\.\d+)?)/);
  if (m) return parseInt(m[1], 10) * 60 + parseFloat(m[2]);
  return ((idx + 1) / (total + 1)) * mediaDurationSec;
}

function normalizeReportPayload(raw, fallbackReport = null) {
  if (!raw || typeof raw !== "object") return fallbackReport;
  const root = raw.report || raw.case || raw.data || raw;
  const base = fallbackReport || {};

  const evidence = (root.evidence || base.evidence || []).map((ev, idx) => ({
    evidence_id: ev.evidence_id || `EV-${idx + 1}`,
    filename: ev.filename || "evidence_file",
    media_type: ev.media_type || "video",
    size_bytes: ev.size_bytes ?? 0,
    sha256: ev.sha256 || "",
    md5: ev.md5 || "",
    duration_sec: Number(ev.duration_sec || 16.0),
    metadata: ev.metadata || {},
  }));

  const rawIndicators = root.indicators || root.findings || base.indicators || [];
  const indicators = rawIndicators.map((ind, idx) => {
    const conf = Number(ind.calibrated_confidence ?? ind.confidence ?? 0);
    return {
      finding_id: ind.finding_id || `F-${String(idx + 1).padStart(3, "0")}`,
      evidence_id: ind.evidence_id || evidence[0]?.evidence_id || "",
      modality: ind.modality || "video",
      location: ind.location || `00:${String((idx + 1) * 3).padStart(2, "0")}.0`,
      timestamp_sec: parseTimestampSec(ind, idx, rawIndicators.length),
      bbox: ind.bbox || { x: 0.34, y: 0.24, w: 0.32, h: 0.42 },
      signal_summary: ind.signal_summary || ind.summary || "Forensic anomaly detected",
      calibrated_confidence: conf,
      fraud_label: ind.fraud_label || (conf >= 0.7 ? "FAKE" : "SUSPICIOUS"),
      disposition: ind.disposition || "Unreviewed",
      reviewer_note: ind.reviewer_note ?? "",
    };
  });

  return {
    case_id: root.case_id || base.case_id || "CASE-UNTITLED",
    claim: root.claim ?? base.claim ?? "",
    verdict: root.verdict || base.verdict || "REVIEW",
    overall_risk_score: root.overall_risk_score ?? base.overall_risk_score ?? 0,
    pipeline_stages: root.pipeline_stages || base.pipeline_stages || [],
    evidence,
    indicators,
    correlations: root.correlations || base.correlations || [],
    audit_log: root.audit_log || base.audit_log || [],
  };
}

function getSelectedEvidence() {
  if (!currentReport?.evidence?.length) return null;
  return (
    currentReport.evidence.find((e) => e.evidence_id === selectedEvidenceId) ||
    currentReport.evidence[0]
  );
}

async function checkHealth() {
  const statusEl = document.getElementById("connectionStatus");
  try {
    const res = await fetch("/health");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    statusEl.textContent = `● API Nominal · ${data.case_count ?? 0} case(s) indexed`;
    statusEl.className = "conn-indicator ok";
  } catch {
    statusEl.textContent = "▲ API Disconnected";
    statusEl.className = "conn-indicator warn";
  }
}

function ensureAudioSynth() {
  if (audioCtx) return;
  const AudioContextClass = window.AudioContext || window.webkitAudioContext;
  if (!AudioContextClass) return;
  audioCtx = new AudioContextClass();
  analyserNode = audioCtx.createAnalyser();
  analyserNode.fftSize = 128;
  liveFrequencyBins = new Uint8Array(analyserNode.frequencyBinCount);

  synthGain = audioCtx.createGain();
  synthGain.gain.value = 0;

  synthOsc1 = audioCtx.createOscillator();
  synthOsc2 = audioCtx.createOscillator();
  synthOsc1.type = "sawtooth";
  synthOsc2.type = "triangle";
  synthOsc1.frequency.value = 145;
  synthOsc2.frequency.value = 290;

  const filter = audioCtx.createBiquadFilter();
  filter.type = "bandpass";
  filter.frequency.value = 680;
  filter.Q.value = 2.4;

  synthOsc1.connect(filter);
  synthOsc2.connect(filter);
  filter.connect(synthGain);
  synthGain.connect(analyserNode);
  analyserNode.connect(audioCtx.destination);

  synthOsc1.start();
  synthOsc2.start();
}

function updateSynthSound(t, nearFake) {
  if (!audioCtx || !synthGain) return;
  if (!isPlaying || isMuted || uploadedVideoUrl || uploadedAudioUrl) {
    synthGain.gain.setTargetAtTime(0, audioCtx.currentTime, 0.03);
    return;
  }
  const syllable = Math.max(0, Math.sin(t * 9.5)) * (0.5 + 0.5 * Math.cos(t * 3.1));
  const pitch = nearFake ? 215 + Math.sin(t * 48) * 65 : 138 + Math.sin(t * 4.2) * 24;
  synthOsc1.frequency.setTargetAtTime(pitch, audioCtx.currentTime, 0.02);
  synthOsc2.frequency.setTargetAtTime(pitch * 2.02, audioCtx.currentTime, 0.02);
  synthGain.gain.setTargetAtTime(syllable * (nearFake ? 0.14 : 0.07), audioCtx.currentTime, 0.025);
}

function togglePlayPause() {
  const btn = document.getElementById("playPauseBtn");
  const vidEl = document.getElementById("uploadedVideoEl");
  const audEl = document.getElementById("uploadedAudioEl");

  isPlaying = !isPlaying;
  btn.textContent = isPlaying ? "Pause" : "Play Stream";
  document.body.dataset.playback = isPlaying ? "playing" : "paused";

  if (isPlaying) {
    ensureAudioSynth();
    if (audioCtx && audioCtx.state === "suspended") audioCtx.resume();
    if (uploadedVideoUrl) {
      vidEl.muted = isMuted;
      vidEl.playbackRate = playbackRate;
      vidEl.currentTime = playheadSec;
      vidEl.play().catch(() => {});
    }
    if (uploadedAudioUrl) {
      audEl.muted = isMuted;
      audEl.playbackRate = playbackRate;
      audEl.currentTime = playheadSec;
      audEl.play().catch(() => {});
    }
    lastFrameTs = performance.now();
    rafId = requestAnimationFrame(playbackLoop);
  } else {
    if (rafId) cancelAnimationFrame(rafId);
    if (uploadedVideoUrl) vidEl.pause();
    if (uploadedAudioUrl) audEl.pause();
    updateSynthSound(playheadSec, false);
  }
}

function toggleMute() {
  isMuted = !isMuted;
  document.getElementById("muteToggleBtn").textContent = isMuted ? "Muted" : "Audio On";
  document.getElementById("uploadedVideoEl").muted = isMuted;
  document.getElementById("uploadedAudioEl").muted = isMuted;
  if (isMuted) updateSynthSound(playheadSec, false);
}

function cycleSpeed() {
  const speeds = [0.5, 1.0, 2.0];
  const next = speeds[(speeds.indexOf(playbackRate) + 1) % speeds.length];
  playbackRate = next;
  document.getElementById("speedBtn").textContent = `${playbackRate}x`;
  document.getElementById("uploadedVideoEl").playbackRate = playbackRate;
  document.getElementById("uploadedAudioEl").playbackRate = playbackRate;
}

function seekToTime(sec) {
  playheadSec = Math.max(0, Math.min(mediaDurationSec, sec));
  const vidEl = document.getElementById("uploadedVideoEl");
  const audEl = document.getElementById("uploadedAudioEl");
  if (uploadedVideoUrl && Number.isFinite(vidEl.duration)) {
    vidEl.currentTime = Math.min(vidEl.duration, playheadSec);
  }
  if (uploadedAudioUrl && Number.isFinite(audEl.duration)) {
    audEl.currentTime = Math.min(audEl.duration, playheadSec);
  }
  renderVisualAndTracks();
}

function playbackLoop(now) {
  if (!isPlaying) return;
  const dt = lastFrameTs ? ((now - lastFrameTs) / 1000) * playbackRate : 0.016;
  lastFrameTs = now;

  const vidEl = document.getElementById("uploadedVideoEl");
  if (uploadedVideoUrl && !vidEl.paused && Number.isFinite(vidEl.duration)) {
    mediaDurationSec = vidEl.duration || mediaDurationSec;
    playheadSec = vidEl.currentTime;
  } else {
    playheadSec += dt;
    if (playheadSec >= mediaDurationSec) playheadSec = 0;
  }

  if (analyserNode && liveFrequencyBins) {
    analyserNode.getByteFrequencyData(liveFrequencyBins);
  }

  renderVisualAndTracks();
  rafId = requestAnimationFrame(playbackLoop);
}

function updateVerdictBanner(report) {
  const banner = document.getElementById("verdictBanner");
  const flag = document.getElementById("verdictFlag");
  const headline = document.getElementById("verdictHeadline");
  const detail = document.getElementById("verdictDetail");
  const scoreEl = document.getElementById("verdictScore");

  const indicators = (report && report.indicators) || [];
  const fakeList = indicators.filter(isFakeIndicator);
  const reviewList = indicators.filter(
    (i) =>
      !isFakeIndicator(i) &&
      i.disposition !== "Benign Artifact" &&
      i.disposition !== "Confirmed Authentic" &&
      (i.fraud_label === "SUSPICIOUS" || Number(i.calibrated_confidence || 0) >= 0.45),
  );

  if (fakeList.length > 0) {
    const maxConf = fakeList.reduce((m, i) => Math.max(m, Number(i.calibrated_confidence || 0)), 0);
    banner.className = "verdict-banner fake";
    flag.className = "status-tag fake";
    flag.textContent = `✖ FAKE / FRAUD (${fakeList.length} FLAG${fakeList.length > 1 ? "S" : ""})`;
    headline.textContent = "Manipulated or Synthetic Media Detected";
    detail.textContent = fakeList
      .slice(0, 2)
      .map((f) => `${f.modality.toUpperCase()} @ ${f.location} — ${f.signal_summary}`)
      .join(" · ");
    scoreEl.textContent = `${Math.round(maxConf * 100)}%`;
    scoreEl.style.color = "var(--bad)";
  } else if (reviewList.length > 0) {
    const maxConf = reviewList.reduce((m, i) => Math.max(m, Number(i.calibrated_confidence || 0)), 0);
    banner.className = "verdict-banner review";
    flag.className = "status-tag warn";
    flag.textContent = `▲ NEEDS REVIEW (${reviewList.length})`;
    headline.textContent = "Suspicious Editing or Container Traces Present";
    detail.textContent = reviewList
      .slice(0, 2)
      .map((f) => `${f.modality.toUpperCase()} @ ${f.location} — ${f.signal_summary}`)
      .join(" · ");
    scoreEl.textContent = `${Math.round(maxConf * 100)}%`;
    scoreEl.style.color = "var(--warn)";
  } else {
    banner.className = "verdict-banner authentic";
    flag.className = "status-tag ok";
    flag.textContent = "● AUTHENTIC / VERIFIED";
    headline.textContent = "No Synthetic or Splicing Manipulation Flagged";
    detail.textContent = "Bitstreams, container headers, and entropy profiles passed forensic integrity checks.";
    scoreEl.textContent = "0%";
    scoreEl.style.color = "var(--ok)";
  }
}

function renderPipelineStages(stages) {
  const strip = document.getElementById("pipelineStrip");
  const list = stages && stages.length ? stages : STAGES.map((name) => ({ name, status: "completed" }));
  strip.innerHTML = list
    .map(
      (st, idx) => `
      <div class="stage done">
        <div class="s-name">${escapeHtml(st.name || STAGES[idx])}</div>
        <div class="s-state">${escapeHtml(st.status || "completed")}${st.duration_ms ? ` · ${st.duration_ms} ms` : ""}</div>
      </div>`,
    )
    .join("");
}

function renderEvidence(items, indicators) {
  const el = document.getElementById("evidenceContainer");
  if (!items || !items.length) {
    el.innerHTML = '<div class="empty">No evidence loaded. Upload media or select a saved case.</div>';
    return;
  }
  el.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Filename &amp; Magic</th>
          <th>Modality</th>
          <th>Size</th>
          <th>Status</th>
          <th>SHA-256 Digest</th>
        </tr>
      </thead>
      <tbody>
        ${items
          .map((ev) => {
            const hasFake = (indicators || []).some(
              (i) => i.evidence_id === ev.evidence_id && isFakeIndicator(i),
            );
            const verdictTag = hasFake
              ? '<span class="status-tag fake">✖ FAKE</span>'
              : '<span class="status-tag ok">● AUTHENTIC</span>';
            const magic = ev.metadata?.detected_magic || ev.metadata?.content_type || "";
            const isSel = ev.evidence_id === selectedEvidenceId;
            return `
              <tr class="${isSel ? "row-selected" : ""}">
                <td>
                  <button type="button" class="link-btn mono" data-inspect-ev="${escapeHtml(ev.evidence_id)}">
                    ${escapeHtml(ev.evidence_id)}
                  </button>
                </td>
                <td>
                  <div>${escapeHtml(ev.filename)}</div>
                  <div class="sub-meta">${escapeHtml(magic)}</div>
                </td>
                <td class="mono">${escapeHtml(ev.media_type)}</td>
                <td class="mono">${escapeHtml(formatBytes(ev.size_bytes))}</td>
                <td>${verdictTag}</td>
                <td>
                  <div class="hash-cell">
                    <code class="mono">${escapeHtml(String(ev.sha256 || "").slice(0, 16))}…</code>
                    <button type="button" class="mini-btn" data-copy-hash="${escapeHtml(ev.sha256 || "")}" aria-label="Copy SHA-256 for ${escapeHtml(ev.filename)}">Copy</button>
                  </div>
                </td>
              </tr>`;
          })
          .join("")}
      </tbody>
    </table>
  `;
}

function renderHexAndMetadataPanel() {
  const box = document.getElementById("hexInspectorContent");
  const ev = getSelectedEvidence();
  if (!ev) {
    box.innerHTML = '<div class="empty">Select an evidence item to inspect cryptographic hashes, container signatures, and binary headers.</div>';
    return;
  }
  const m = ev.metadata || {};
  const sigs = (m.software_signatures || []).length
    ? m.software_signatures.map((s) => `<span class="status-tag warn">${escapeHtml(s)}</span>`).join(" ")
    : '<span class="sub-meta">None detected</span>';

  box.innerHTML = `
    <div class="meta-kv-grid">
      <div class="meta-kv"><span class="k">Evidence Item</span><span class="v mono">${escapeHtml(ev.evidence_id)} · ${escapeHtml(ev.filename)}</span></div>
      <div class="meta-kv"><span class="k">Detected Magic</span><span class="v mono">${escapeHtml(m.detected_magic || "Unknown")}</span></div>
      <div class="meta-kv"><span class="k">Extension Match</span><span class="v mono">${m.extension_match === false ? "✖ MISMATCH (SPOOFED)" : "● VERIFIED"}</span></div>
      <div class="meta-kv"><span class="k">Shannon Entropy</span><span class="v mono">${Number(m.shannon_entropy ?? 0).toFixed(4)} bits/byte</span></div>
      <div class="meta-kv"><span class="k">C2PA Provenance</span><span class="v mono">${m.c2pa_present ? "● PRESENT" : "ABSENT"}</span></div>
      <div class="meta-kv"><span class="k">Camera EXIF</span><span class="v mono">${m.exif_present ? "● PRESENT" : "ABSENT"}</span></div>
      <div class="meta-kv full"><span class="k">SHA-256</span><span class="v mono break-all">${escapeHtml(ev.sha256 || "-")}</span></div>
      <div class="meta-kv full"><span class="k">Encoder / Software Signatures</span><span class="v">${sigs}</span></div>
    </div>
    <div class="hex-title">Header Hex Slice (0x0000 – 0x00FF)</div>
    <pre class="hex-dump">${escapeHtml(m.hex_preview || "No binary header slice available.")}</pre>
  `;
}

function renderVisualAndTracks() {
  if (!currentReport) return;

  const indicators = currentReport.indicators || [];
  const activeFindingId = document.getElementById("reviewFindingSelect")?.value || "";
  const videoEvId = document.getElementById("videoTrackSelect")?.value || "";
  const audioEvId = document.getElementById("audioTrackSelect")?.value || "";

  document.getElementById("timecodeDisplay").textContent = `${formatSec(playheadSec)} / ${formatSec(mediaDurationSec)}`;

  const activeFakeAtPlayhead = indicators.find(
    (ind) => isFakeIndicator(ind) && Math.abs((ind.timestamp_sec ?? 0) - playheadSec) <= 1.15,
  );

  updateSynthSound(playheadSec, Boolean(activeFakeAtPlayhead));

  const alertTag = document.getElementById("liveDetectionAlert");
  const hudStatus = document.getElementById("hudStatusLabel");
  if (activeFakeAtPlayhead) {
    alertTag.className = "status-tag fake";
    alertTag.textContent = `✖ FAKE: ${activeFakeAtPlayhead.finding_id} (${Math.round(activeFakeAtPlayhead.calibrated_confidence * 100)}%)`;
    hudStatus.textContent = `ANOMALY @ ${formatSec(playheadSec)}`;
    hudStatus.style.color = "#fca5a5";
  } else {
    alertTag.className = "status-tag ok";
    alertTag.textContent = "● MONITORING";
    hudStatus.textContent = `PLAYHEAD ${formatSec(playheadSec)}`;
    hudStatus.style.color = "#93c5fd";
  }

  renderViewportCanvas({
    canvas: document.getElementById("videoViewportCanvas"),
    uploadedImageEl,
    hasVideo: Boolean(uploadedVideoUrl),
    playheadSec,
    isPlaying,
    activeFakeAtPlayhead,
    filterMode: activeFilterMode,
    hoverPos,
  });

  if (activeViewportTab === "entropy") {
    const ev = getSelectedEvidence();
    document.getElementById("entropyMetaLabel").textContent = ev
      ? `${ev.evidence_id} · ${ev.filename} · Global Entropy ${Number(ev.metadata?.shannon_entropy ?? 0).toFixed(3)} b/B`
      : "No evidence selected";
    renderEntropyCanvas({
      canvas: document.getElementById("entropyChartCanvas"),
      evidenceItem: ev,
      hoverBinIdx,
    });
  } else if (activeViewportTab === "hex") {
    renderHexAndMetadataPanel();
  }

  drawTrackCanvas({
    canvasId: "videoTimelineCanvas",
    mode: "video",
    indicators: indicators.filter((i) => !videoEvId || i.evidence_id === videoEvId || i.modality === "video"),
    activeFindingId,
    playheadSec,
    mediaDurationSec,
    liveFrequencyBins: null,
    isPlaying,
  });

  drawTrackCanvas({
    canvasId: "audioSpectrogramCanvas",
    mode: "audio",
    indicators: indicators.filter((i) => !audioEvId || i.evidence_id === audioEvId || i.modality === "audio"),
    activeFindingId,
    playheadSec,
    mediaDurationSec,
    liveFrequencyBins,
    isPlaying,
  });

  const markersBox = document.getElementById("timelineMarkersList");
  if (!indicators.length) {
    markersBox.innerHTML = '<div class="empty">No timeline markers.</div>';
  } else {
    markersBox.innerHTML = `<div class="marker-row">${indicators
      .map((ind) => {
        const fake = isFakeIndicator(ind);
        const selected = ind.finding_id === activeFindingId;
        return `
          <button
            type="button"
            class="marker-btn ${fake ? "danger" : "secondary"} ${selected ? "selected" : ""}"
            data-jump-finding="${escapeHtml(ind.finding_id)}"
          >
            ${fake ? "FAKE" : "VERIFIED"} · ${escapeHtml(ind.finding_id)} @ ${formatSec(ind.timestamp_sec)}
          </button>`;
      })
      .join("")}</div>`;
  }
}

function switchViewportTab(tab) {
  activeViewportTab = tab;
  document.querySelectorAll("[data-viewport-tab]").forEach((btn) => {
    const isActive = btn.getAttribute("data-viewport-tab") === tab;
    btn.classList.toggle("active", isActive);
    btn.setAttribute("aria-selected", String(isActive));
  });
  document.getElementById("visualStagePane").hidden = tab !== "visual";
  document.getElementById("entropyStagePane").hidden = tab !== "entropy";
  document.getElementById("hexStagePane").hidden = tab !== "hex";
  renderVisualAndTracks();
}

function populateTrackSelectors(evidence) {
  const vSel = document.getElementById("videoTrackSelect");
  const aSel = document.getElementById("audioTrackSelect");
  const hexSel = document.getElementById("evidenceInspectSelect");
  vSel.innerHTML = "";
  aSel.innerHTML = "";
  hexSel.innerHTML = "";

  const items = evidence || [];
  if (!items.length) {
    vSel.innerHTML = '<option value="">No video track</option>';
    aSel.innerHTML = '<option value="">No audio track</option>';
    hexSel.innerHTML = '<option value="">No evidence</option>';
    return;
  }

  items.forEach((ev) => {
    const label = `${ev.evidence_id} (${ev.filename})`;
    [vSel, aSel, hexSel].forEach((sel) => {
      const opt = document.createElement("option");
      opt.value = ev.evidence_id;
      opt.textContent = label;
      sel.appendChild(opt);
    });
  });

  const firstVid = items.find((e) => e.media_type === "video") || items[0];
  const firstAud = items.find((e) => e.media_type === "audio") || items[0];
  vSel.value = firstVid.evidence_id;
  aSel.value = firstAud.evidence_id;
  if (!selectedEvidenceId || !items.some((e) => e.evidence_id === selectedEvidenceId)) {
    selectedEvidenceId = items[0].evidence_id;
  }
  hexSel.value = selectedEvidenceId;
}

function renderIndicators(indicators) {
  const container = document.getElementById("indicatorsContainer");
  const q = (document.getElementById("searchInput").value || "").trim().toLowerCase();
  const mod = document.getElementById("modalityFilter").value;
  const disp = document.getElementById("dispositionFilter").value;

  const filtered = (indicators || []).filter((ind) => {
    if (mod && ind.modality !== mod) return false;
    if (disp && (ind.disposition || "Unreviewed") !== disp) return false;
    if (q) {
      const lbl = isFakeIndicator(ind) ? "fake fraud" : String(ind.fraud_label || "authentic").toLowerCase();
      const hay = `${ind.finding_id} ${ind.evidence_id} ${ind.location} ${ind.signal_summary} ${ind.reviewer_note || ""} ${lbl}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  if (!filtered.length) {
    container.innerHTML = '<div class="empty">No matching forensic indicators.</div>';
    return;
  }

  const selectedId = document.getElementById("reviewFindingSelect")?.value || "";

  container.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Finding</th>
          <th>Classification</th>
          <th>Modality</th>
          <th>Location</th>
          <th>Signal Summary</th>
          <th class="num">Conf.</th>
          <th>Disposition</th>
        </tr>
      </thead>
      <tbody>
        ${filtered
          .map((ind) => {
            const isSelected = ind.finding_id === selectedId;
            const fake = isFakeIndicator(ind);
            const lbl = String(ind.fraud_label || "").toUpperCase();
            const labelHtml = fake
              ? '<span class="status-tag fake">✖ FAKE</span>'
              : lbl === "AUTHENTIC"
                ? '<span class="status-tag ok">● AUTHENTIC</span>'
                : '<span class="status-tag warn">▲ SUSPICIOUS</span>';

            return `
              <tr
                data-finding-id="${escapeHtml(ind.finding_id)}"
                class="${isSelected ? "row-selected" : ""}"
              >
                <td>
                  <button type="button" class="link-btn mono" data-jump-finding="${escapeHtml(ind.finding_id)}">
                    ${escapeHtml(ind.finding_id)}
                  </button>
                  <div class="sub-meta mono">${escapeHtml(ind.evidence_id)}</div>
                </td>
                <td>${labelHtml}</td>
                <td class="mono">${escapeHtml(ind.modality)}</td>
                <td><code class="mono">${escapeHtml(ind.location)}</code></td>
                <td>${escapeHtml(ind.signal_summary)}</td>
                <td class="num mono"><strong>${Number(ind.calibrated_confidence ?? 0).toFixed(2)}</strong></td>
                <td class="mono">${escapeHtml(ind.disposition || "Unreviewed")}</td>
              </tr>`;
          })
          .join("")}
      </tbody>
    </table>
  `;
}

function populateReviewSelector(indicators, preferredId = "") {
  const sel = document.getElementById("reviewFindingSelect");
  const saveBtn = document.getElementById("saveReviewBtn");
  sel.innerHTML = "";

  if (!indicators || !indicators.length) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "No findings available";
    sel.appendChild(opt);
    saveBtn.disabled = true;
    document.querySelectorAll("[data-quick-disp]").forEach((b) => (b.disabled = true));
    return;
  }

  indicators.forEach((ind) => {
    const opt = document.createElement("option");
    opt.value = ind.finding_id;
    opt.textContent = `${ind.finding_id} [${ind.fraud_label}] (${ind.modality} · ${ind.location})`;
    sel.appendChild(opt);
  });

  if (preferredId && indicators.some((i) => i.finding_id === preferredId)) {
    sel.value = preferredId;
  }
  saveBtn.disabled = false;
  document.querySelectorAll("[data-quick-disp]").forEach((b) => (b.disabled = false));
  syncReviewInputsFromSelected();
}

function syncReviewInputsFromSelected() {
  if (!currentReport) return;
  const fid = document.getElementById("reviewFindingSelect").value;
  const ind = (currentReport.indicators || []).find((i) => i.finding_id === fid);
  if (!ind) return;
  document.getElementById("reviewDispositionSelect").value = ind.disposition || "Unreviewed";
  document.getElementById("reviewNoteInput").value = ind.reviewer_note || "";
  if (ind.evidence_id) {
    selectedEvidenceId = ind.evidence_id;
    const hexSel = document.getElementById("evidenceInspectSelect");
    if (hexSel) hexSel.value = selectedEvidenceId;
  }

  document.querySelectorAll("#indicatorsContainer tbody tr[data-finding-id]").forEach((tr) => {
    tr.classList.toggle("row-selected", tr.getAttribute("data-finding-id") === fid);
  });
  renderVisualAndTracks();
}

function jumpToFinding(findingId) {
  const sel = document.getElementById("reviewFindingSelect");
  if (!sel || !findingId || !currentReport) return;
  sel.value = findingId;
  syncReviewInputsFromSelected();
  const ind = (currentReport.indicators || []).find((i) => i.finding_id === findingId);
  if (ind && typeof ind.timestamp_sec === "number") seekToTime(ind.timestamp_sec);
}

function jumpToNextFakeAnomaly() {
  if (!currentReport) return;
  const fakes = (currentReport.indicators || [])
    .filter(isFakeIndicator)
    .sort((a, b) => (a.timestamp_sec ?? 0) - (b.timestamp_sec ?? 0));
  if (!fakes.length) return;
  const next = fakes.find((f) => (f.timestamp_sec ?? 0) > playheadSec + 0.25) || fakes[0];
  jumpToFinding(next.finding_id);
}

function stepReviewFinding(delta) {
  const sel = document.getElementById("reviewFindingSelect");
  if (!sel || sel.options.length === 0) return;
  const total = sel.options.length;
  const currentIdx = sel.selectedIndex >= 0 ? sel.selectedIndex : 0;
  sel.selectedIndex = (currentIdx + delta + total) % total;
  jumpToFinding(sel.value);
}

function renderCorrelations(correlations) {
  const el = document.getElementById("correlationsContainer");
  if (!correlations || !correlations.length) {
    el.innerHTML = '<div class="empty">No cross-evidence correlations computed.</div>';
    return;
  }
  el.innerHTML = `<ul class="clean">${correlations
    .map(
      (c) =>
        `<li><code class="mono">${escapeHtml(c.correlation_id || "CORR")}</code> · <strong>${escapeHtml(c.relation || "")}</strong> (score <span class="mono">${Number(c.score ?? 0).toFixed(2)}</span>): ${escapeHtml(c.summary || "")}</li>`,
    )
    .join("")}</ul>`;
}

function renderAuditLog(events) {
  const el = document.getElementById("auditContainer");
  if (!events || !events.length) {
    el.innerHTML = '<div class="empty">No audit events recorded.</div>';
    return;
  }
  el.innerHTML = `<ul class="clean">${events
    .map(
      (ev) =>
        `<li><code class="mono">${escapeHtml(ev.timestamp || "")}</code> — <strong>${escapeHtml(ev.action || "")}</strong>: ${escapeHtml(ev.detail || "")}</li>`,
    )
    .join("")}</ul>`;
}

function renderReport(report, preferredFindingId = "") {
  currentReport = report;
  const indicators = report.indicators || [];
  const fakeCount = indicators.filter(isFakeIndicator).length;

  mediaDurationSec = Math.max(
    8.0,
    ...(report.evidence || []).map((e) => Number(e.duration_sec || 16.0)),
    ...indicators.map((i) => Number(i.timestamp_sec || 0) + 2.0),
  );

  document.getElementById("caseTitle").textContent = report.case_id;
  document.getElementById("claimDisplay").textContent = report.claim || "No claim statement provided";
  document.getElementById("mEvidence").textContent = String((report.evidence || []).length);
  document.getElementById("mIndicators").textContent = String(indicators.length);
  document.getElementById("mFakeFlags").textContent = String(fakeCount);
  document.getElementById("mCorrelations").textContent = String((report.correlations || []).length);
  document.getElementById("exportReportBtn").disabled = !report.case_id;

  updateVerdictBanner(report);
  renderPipelineStages(report.pipeline_stages || []);
  populateTrackSelectors(report.evidence || []);
  renderEvidence(report.evidence || [], indicators);
  populateReviewSelector(indicators, preferredFindingId);
  renderIndicators(indicators);
  renderCorrelations(report.correlations || []);
  renderAuditLog(report.audit_log || []);
  renderVisualAndTracks();
}

function clearLocalUploadedMedia() {
  if (uploadedVideoUrl) {
    URL.revokeObjectURL(uploadedVideoUrl);
    uploadedVideoUrl = null;
  }
  if (uploadedAudioUrl) {
    URL.revokeObjectURL(uploadedAudioUrl);
    uploadedAudioUrl = null;
  }
  uploadedImageEl = null;
  const vidEl = document.getElementById("uploadedVideoEl");
  vidEl.style.display = "none";
  vidEl.removeAttribute("src");
  const audEl = document.getElementById("uploadedAudioEl");
  audEl.removeAttribute("src");
}

function resetActiveCaseView() {
  if (isPlaying) togglePlayPause();
  playheadSec = 0;
  currentReport = null;
  selectedEvidenceId = "";
  pendingFiles = [];
  renderPendingFiles();
  clearLocalUploadedMedia();

  document.getElementById("analyzeForm").reset();
  document.getElementById("searchInput").value = "";
  document.getElementById("modalityFilter").value = "";
  document.getElementById("dispositionFilter").value = "";
  document.getElementById("caseTitle").textContent = "None Loaded";
  document.getElementById("claimDisplay").textContent = "Select a saved case or ingest new evidence";
  document.getElementById("mEvidence").textContent = "0";
  document.getElementById("mIndicators").textContent = "0";
  document.getElementById("mFakeFlags").textContent = "0";
  document.getElementById("mCorrelations").textContent = "0";
  document.getElementById("exportReportBtn").disabled = true;

  renderEvidence([], []);
  renderIndicators([]);
  populateReviewSelector([]);
  renderCorrelations([]);
  renderAuditLog([]);
  renderVisualAndTracks();
}

async function loadCasesList() {
  const sel = document.getElementById("casesSelect");
  const status = document.getElementById("casesStatus");
  try {
    const res = await fetch("/cases");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const cases = data.cases || [];
    sel.innerHTML = "";
    if (!cases.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "No saved cases";
      sel.appendChild(opt);
      status.textContent = "No saved cases on server.";
      return;
    }
    cases.forEach((c) => {
      const slug = typeof c === "string" ? c : c.slug || c.case_id;
      const opt = document.createElement("option");
      opt.value = slug;
      const verdictTxt = c.verdict ? ` · ${c.verdict}` : "";
      opt.textContent = `${c.case_id || slug} (${c.indicator_count ?? 0} ind.${verdictTxt})`;
      sel.appendChild(opt);
    });
    if (currentReport?.case_id && cases.some((c) => (c.slug || c.case_id) === currentReport.case_id)) {
      sel.value = currentReport.case_id;
    }
    status.textContent = `${cases.length} case(s) in archive.`;
    status.className = "status-msg";
  } catch {
    status.textContent = "Unable to reach /cases endpoint.";
    status.className = "status-msg err";
  }
}

async function loadCaseBySlug(slug) {
  if (!slug) return;
  const status = document.getElementById("casesStatus");
  clearLocalUploadedMedia();
  try {
    const res = await fetch(`/cases/${encodeURIComponent(slug)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const raw = await res.json();
    selectedEvidenceId = "";
    renderReport(normalizeReportPayload(raw));
    status.textContent = `Loaded ${slug}.`;
    status.className = "status-msg ok";
  } catch (err) {
    status.textContent = `Load error: ${err.message}`;
    status.className = "status-msg err";
  }
}

function attachLocalUploadedMedia(files) {
  clearLocalUploadedMedia();
  const vidEl = document.getElementById("uploadedVideoEl");
  const audEl = document.getElementById("uploadedAudioEl");

  for (const f of files) {
    if (f.type.startsWith("video/")) {
      uploadedVideoUrl = URL.createObjectURL(f);
      vidEl.src = uploadedVideoUrl;
      vidEl.style.display = "block";
      document.getElementById("hudTrackLabel").textContent = `VIDEO · ${f.name}`;
    } else if (f.type.startsWith("audio/")) {
      uploadedAudioUrl = URL.createObjectURL(f);
      audEl.src = uploadedAudioUrl;
      document.getElementById("hudTrackLabel").textContent = `AUDIO · ${f.name}`;
    } else if (f.type.startsWith("image/") || /\.(png|jpe?g|webp|bmp)$/i.test(f.name)) {
      const url = URL.createObjectURL(f);
      const img = new Image();
      img.onload = () => {
        uploadedImageEl = img;
        renderVisualAndTracks();
      };
      img.src = url;
      document.getElementById("hudTrackLabel").textContent = `IMAGE · ${f.name}`;
    }
  }
}

function renderPendingFiles() {
  const box = document.getElementById("pendingFilesList");
  if (!pendingFiles.length) {
    box.innerHTML = "";
    return;
  }
  box.innerHTML = pendingFiles
    .map(
      (f, idx) => `
      <div class="queued-file">
        <span class="mono truncate">${escapeHtml(f.name)}</span>
        <span class="sub-meta mono">${escapeHtml(formatBytes(f.size))}</span>
        <button type="button" class="mini-btn" data-remove-file="${idx}" aria-label="Remove ${escapeHtml(f.name)}">Remove</button>
      </div>`,
    )
    .join("");
}

function stageFiles(fileList) {
  const arr = Array.from(fileList || []);
  if (!arr.length) return;
  pendingFiles = [...pendingFiles, ...arr];
  renderPendingFiles();
}

function buildSampleArtifact(preset) {
  if (preset === "spoofed-mp4") {
    const payload = new TextEncoder().encode(
      "Lavf60.3.100 FFmpeg re-muxed synthetic executive clip without valid ftyp atom",
    );
    return {
      caseId: `CASE-SPOOF-${Math.floor(100 + Math.random() * 899)}`,
      claim: "Suspected re-muxed executive authorization clip with mismatched binary magic",
      file: new File([payload], "wire_authorization_clip.mp4", { type: "video/mp4" }),
    };
  }
  if (preset === "ai-png") {
    const pngSig = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const textChunk = new TextEncoder().encode(
      "IHDR....tEXtparameters\x00executive portrait, Steps: 32, Sampler: DPM++ 2M, CFG scale: 7.5, ComfyUI",
    );
    const merged = new Uint8Array(pngSig.length + textChunk.length);
    merged.set(pngSig, 0);
    merged.set(textChunk, pngSig.length);
    return {
      caseId: `CASE-GEN-${Math.floor(100 + Math.random() * 899)}`,
      claim: "Identity badge photo suspected of Stable Diffusion / ComfyUI synthesis",
      file: new File([merged], "executive_badge_render.png", { type: "image/png" }),
    };
  }
  // Authentic hardware JPEG
  const jpgHeader = new Uint8Array([0xff, 0xd8, 0xff, 0xe1, 0x00, 0x40]);
  const exif = new TextEncoder().encode("Exif\x00\x00Canon EOS R5 DateTimeOriginal 2026:11:19 c2pa jumbf");
  const body = new Uint8Array(1024).fill(0x5a);
  const merged = new Uint8Array(jpgHeader.length + exif.length + body.length);
  merged.set(jpgHeader, 0);
  merged.set(exif, jpgHeader.length);
  merged.set(body, jpgHeader.length + exif.length);
  return {
    caseId: `CASE-CAM-${Math.floor(100 + Math.random() * 899)}`,
    claim: "Hardware camera-original still with intact EXIF and C2PA Content Credentials",
    file: new File([merged], "camera_original_eos_r5.jpg", { type: "image/jpeg" }),
  };
}

async function submitPatchDisposition(fid, disposition, reviewerNote) {
  if (!currentReport || !fid) return;
  const reviewStatus = document.getElementById("reviewStatus");
  try {
    const slug = encodeURIComponent(currentReport.case_id);
    const res = await fetch(`/cases/${slug}/indicators/${encodeURIComponent(fid)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ disposition, reviewer_note: reviewerNote }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const raw = await res.json();
    renderReport(normalizeReportPayload(raw, currentReport), fid);
    await loadCasesList();
    reviewStatus.textContent = `Saved ${fid} → ${disposition}`;
    reviewStatus.className = "status-msg ok";
  } catch (err) {
    reviewStatus.textContent = `Save failed: ${err.message}`;
    reviewStatus.className = "status-msg err";
  }
}

async function openExportModal() {
  if (!currentReport?.case_id) return;
  const modal = document.getElementById("exportModal");
  const slug = encodeURIComponent(currentReport.case_id);
  document.getElementById("dlHtmlLink").href = `/cases/${slug}/report.html`;
  document.getElementById("dlHtmlLink").download = `${currentReport.case_id}-report.html`;
  document.getElementById("dlJsonLink").href = `/cases/${slug}/report.json`;
  document.getElementById("dlJsonLink").download = `${currentReport.case_id}-forensic-bundle.json`;
  document.getElementById("dlCsvLink").href = `/cases/${slug}/report.csv`;
  document.getElementById("dlCsvLink").download = `${currentReport.case_id}-findings.csv`;
  document.getElementById("reportPreviewFrame").src = `/cases/${slug}/report.html`;
  modal.showModal();
}

function wireEvents() {
  // Drag and drop zone
  const dropzone = document.getElementById("dropzone");
  const filesInput = document.getElementById("filesInput");

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("drag-over");
  });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag-over"));
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("drag-over");
    stageFiles(e.dataTransfer?.files);
  });
  filesInput.addEventListener("change", () => {
    stageFiles(filesInput.files);
    filesInput.value = "";
  });

  document.getElementById("pendingFilesList").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-remove-file]");
    if (!btn) return;
    const idx = Number(btn.getAttribute("data-remove-file"));
    pendingFiles.splice(idx, 1);
    renderPendingFiles();
  });

  document.querySelectorAll("[data-sample-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const preset = btn.getAttribute("data-sample-preset");
      const sample = buildSampleArtifact(preset);
      document.getElementById("caseIdInput").value = sample.caseId;
      document.getElementById("claimInput").value = sample.claim;
      pendingFiles = [sample.file];
      renderPendingFiles();
    });
  });

  document.getElementById("analyzeForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = document.getElementById("analyzeBtn");
    const status = document.getElementById("analyzeStatus");
    const caseId = document.getElementById("caseIdInput").value.trim();
    const claim = document.getElementById("claimInput").value.trim();
    if (!caseId) return;

    btn.disabled = true;
    status.textContent = "Running binary & container forensic pipeline...";
    status.className = "status-msg";

    if (pendingFiles.length) attachLocalUploadedMedia(pendingFiles);

    try {
      const fd = new FormData();
      fd.append("case_id", caseId);
      fd.append("claim", claim);
      for (const f of pendingFiles) fd.append("files", f);

      const res = await fetch("/analyze", { method: "POST", body: fd });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const raw = await res.json();
      const report = normalizeReportPayload(raw);
      selectedEvidenceId = "";
      renderReport(report);
      await loadCasesList();
      await checkHealth();
      status.textContent = `Analyzed & archived ${report.case_id}.`;
      status.className = "status-msg ok";
    } catch (err) {
      status.textContent = `Analysis error: ${err.message}`;
      status.className = "status-msg err";
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById("playPauseBtn").addEventListener("click", togglePlayPause);
  document.getElementById("muteToggleBtn").addEventListener("click", toggleMute);
  document.getElementById("speedBtn").addEventListener("click", cycleSpeed);
  document.getElementById("stepBackBtn").addEventListener("click", () => seekToTime(playheadSec - 1 / 30));
  document.getElementById("stepFwdBtn").addEventListener("click", () => seekToTime(playheadSec + 1 / 30));
  document.getElementById("nextFakeBtn").addEventListener("click", jumpToNextFakeAnomaly);

  // Viewport tabs & forensic filters
  document.querySelectorAll("[data-viewport-tab]").forEach((btn) => {
    btn.addEventListener("click", () => switchViewportTab(btn.getAttribute("data-viewport-tab")));
  });

  document.querySelectorAll("[data-filter-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      activeFilterMode = btn.getAttribute("data-filter-mode");
      document.querySelectorAll("[data-filter-mode]").forEach((b) => {
        b.classList.toggle("active", b.getAttribute("data-filter-mode") === activeFilterMode);
      });
      renderVisualAndTracks();
    });
  });

  // Canvas crosshair probe
  const vCanvas = document.getElementById("videoViewportCanvas");
  vCanvas.addEventListener("mousemove", (e) => {
    const rect = vCanvas.getBoundingClientRect();
    hoverPos = {
      x: ((e.clientX - rect.left) / rect.width) * vCanvas.width,
      y: ((e.clientY - rect.top) / rect.height) * vCanvas.height,
    };
    if (!isPlaying) renderVisualAndTracks();
  });
  vCanvas.addEventListener("mouseleave", () => {
    hoverPos = null;
    if (!isPlaying) renderVisualAndTracks();
  });

  // Entropy chart hover probe
  const eCanvas = document.getElementById("entropyChartCanvas");
  eCanvas.addEventListener("mousemove", (e) => {
    const ev = getSelectedEvidence();
    const bins = ev?.metadata?.entropy_bins || [];
    if (!bins.length) return;
    const rect = eCanvas.getBoundingClientRect();
    const cx = ((e.clientX - rect.left) / rect.width) * eCanvas.width;
    const plotW = eCanvas.width - 42 - 16;
    const ratio = Math.max(0, Math.min(1, (cx - 42) / plotW));
    hoverBinIdx = Math.round(ratio * (bins.length - 1));
    renderEntropyCanvas({ canvas: eCanvas, evidenceItem: ev, hoverBinIdx });
  });
  eCanvas.addEventListener("mouseleave", () => {
    hoverBinIdx = null;
    renderEntropyCanvas({ canvas: eCanvas, evidenceItem: getSelectedEvidence(), hoverBinIdx: null });
  });

  // Interactive scrubbers (click & drag) on timeline and spectrogram
  ["videoTimelineCanvas", "audioSpectrogramCanvas"].forEach((id) => {
    const c = document.getElementById(id);
    let dragging = false;
    const scrub = (clientX) => {
      const rect = c.getBoundingClientRect();
      const ratio = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
      seekToTime(ratio * mediaDurationSec);
    };
    c.addEventListener("mousedown", (e) => {
      dragging = true;
      scrub(e.clientX);
    });
    window.addEventListener("mousemove", (e) => {
      if (dragging) scrub(e.clientX);
    });
    window.addEventListener("mouseup", () => {
      dragging = false;
    });
  });

  document.getElementById("videoTrackSelect").addEventListener("change", renderVisualAndTracks);
  document.getElementById("audioTrackSelect").addEventListener("change", renderVisualAndTracks);
  document.getElementById("evidenceInspectSelect").addEventListener("change", (e) => {
    selectedEvidenceId = e.target.value;
    renderEvidence(currentReport?.evidence || [], currentReport?.indicators || []);
    renderVisualAndTracks();
  });

  // Delegated click handlers for evidence inspect, copy hash, marker buttons, indicator rows
  document.getElementById("evidenceContainer").addEventListener("click", (e) => {
    const copyBtn = e.target.closest("[data-copy-hash]");
    if (copyBtn) {
      const hash = copyBtn.getAttribute("data-copy-hash");
      navigator.clipboard?.writeText(hash).catch(() => {});
      copyBtn.textContent = "Copied";
      setTimeout(() => (copyBtn.textContent = "Copy"), 1200);
      return;
    }
    const inspectBtn = e.target.closest("[data-inspect-ev]");
    if (inspectBtn) {
      selectedEvidenceId = inspectBtn.getAttribute("data-inspect-ev");
      document.getElementById("evidenceInspectSelect").value = selectedEvidenceId;
      switchViewportTab("hex");
      renderEvidence(currentReport?.evidence || [], currentReport?.indicators || []);
    }
  });

  document.getElementById("timelineMarkersList").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-jump-finding]");
    if (btn) jumpToFinding(btn.getAttribute("data-jump-finding"));
  });

  document.getElementById("indicatorsContainer").addEventListener("click", (e) => {
    const row = e.target.closest("tr[data-finding-id]");
    if (row) jumpToFinding(row.getAttribute("data-finding-id"));
  });

  document.getElementById("exportReportBtn").addEventListener("click", openExportModal);
  document.getElementById("closeExportModalBtn").addEventListener("click", () => {
    document.getElementById("exportModal").close();
  });
  document.getElementById("openShortcutsBtn").addEventListener("click", () => {
    document.getElementById("shortcutsModal").showModal();
  });
  document.getElementById("closeShortcutsBtn").addEventListener("click", () => {
    document.getElementById("shortcutsModal").close();
  });

  document.getElementById("resetCaseBtn").addEventListener("click", resetActiveCaseView);
  document.getElementById("loadCaseBtn").addEventListener("click", () => {
    loadCaseBySlug(document.getElementById("casesSelect").value);
  });
  document.getElementById("casesSelect").addEventListener("change", (e) => {
    if (e.target.value) loadCaseBySlug(e.target.value);
  });

  document.getElementById("searchInput").addEventListener("input", () => {
    if (currentReport) renderIndicators(currentReport.indicators || []);
  });
  document.getElementById("modalityFilter").addEventListener("change", () => {
    if (currentReport) renderIndicators(currentReport.indicators || []);
  });
  document.getElementById("dispositionFilter").addEventListener("change", () => {
    if (currentReport) renderIndicators(currentReport.indicators || []);
  });
  document.getElementById("reviewFindingSelect").addEventListener("change", syncReviewInputsFromSelected);

  document.getElementById("saveReviewBtn").addEventListener("click", () => {
    const fid = document.getElementById("reviewFindingSelect").value;
    const disposition = document.getElementById("reviewDispositionSelect").value;
    const reviewerNote = document.getElementById("reviewNoteInput").value;
    submitPatchDisposition(fid, disposition, reviewerNote);
  });

  document.querySelectorAll("[data-quick-disp]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const fid = document.getElementById("reviewFindingSelect").value;
      const disposition = btn.getAttribute("data-quick-disp");
      const reviewerNote = document.getElementById("reviewNoteInput").value;
      document.getElementById("reviewDispositionSelect").value = disposition;
      submitPatchDisposition(fid, disposition, reviewerNote);
    });
  });

  // Keyboard shortcuts
  const isEditable = (el) => {
    if (!el) return false;
    const tag = (el.tagName || "").toLowerCase();
    return tag === "input" || tag === "textarea" || tag === "select" || Boolean(el.isContentEditable);
  };

  document.addEventListener("keydown", (e) => {
    if (e.defaultPrevented) return;
    const keyLower = (e.key || "").toLowerCase();
    const editable = isEditable(document.activeElement);

    if (((e.metaKey || e.ctrlKey) && !e.altKey && keyLower === "k") || (!editable && !e.metaKey && !e.ctrlKey && !e.altKey && e.key === "/")) {
      e.preventDefault();
      const s = document.getElementById("searchInput");
      s.focus();
      s.select();
      return;
    }

    if (!editable && !e.metaKey && !e.ctrlKey && !e.altKey && e.key === "?") {
      e.preventDefault();
      document.getElementById("shortcutsModal").showModal();
      return;
    }

    if ((e.metaKey || e.ctrlKey) && !e.altKey && e.key === "Enter") {
      const saveBtn = document.getElementById("saveReviewBtn");
      if (currentReport && saveBtn && !saveBtn.disabled) {
        e.preventDefault();
        saveBtn.click();
      }
      return;
    }

    if (!editable && !e.metaKey && !e.ctrlKey && !e.altKey && e.code === "Space") {
      e.preventDefault();
      togglePlayPause();
      return;
    }

    if (!editable && !e.metaKey && !e.ctrlKey && !e.altKey && (keyLower === "j" || keyLower === "k")) {
      e.preventDefault();
      stepReviewFinding(keyLower === "j" ? 1 : -1);
      return;
    }

    if (e.key === "Escape") {
      document.getElementById("searchInput").value = "";
      document.getElementById("modalityFilter").value = "";
      document.getElementById("dispositionFilter").value = "";
      if (document.activeElement) document.activeElement.blur();
      if (currentReport) renderIndicators(currentReport.indicators || []);
      return;
    }

    if (e.altKey && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
      if (keyLower === "i") {
        e.preventDefault();
        document.getElementById("caseIdInput").focus();
      } else if (keyLower === "d") {
        e.preventDefault();
        document.getElementById("reviewDispositionSelect").focus();
      } else if (keyLower === "n") {
        e.preventDefault();
        document.getElementById("reviewNoteInput").focus();
      } else if (keyLower === "h") {
        e.preventDefault();
        openExportModal();
      }
    }
  });
}

(async function init() {
  wireEvents();
  await checkHealth();
  await loadCasesList();
  await loadCaseBySlug("CASE-2026-0814");
})();
