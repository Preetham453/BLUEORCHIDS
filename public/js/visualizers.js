/**
 * TruthLens Canvas Visualizers & Client-Side Signal Processors
 * Pure rendering functions for Visual Monitor (bounding boxes, ELA/edge residual,
 * luminance heatmap), Entropy Telemetry chart, Video Timeline, and Audio Spectrogram.
 */

export function formatSec(sec) {
  const s = Math.max(0, Number(sec) || 0);
  const mins = Math.floor(s / 60);
  const rem = (s % 60).toFixed(1).padStart(4, "0");
  return `${String(mins).padStart(2, "0")}:${rem}`;
}

export function isFakeIndicator(ind) {
  const conf = Number(ind?.calibrated_confidence ?? 0);
  const disp = String(ind?.disposition || "");
  const lbl = String(ind?.fraud_label || "").toUpperCase();
  if (disp === "Benign Artifact" || disp === "Confirmed Authentic") return false;
  if (lbl === "AUTHENTIC") return false;
  return lbl === "FAKE" || disp === "Confirmed Anomaly" || conf >= 0.7;
}

/**
 * Applies a fast 3x3 Laplacian high-pass edge/noise residual filter or false-color
 * luminance map onto a 2D canvas context containing a drawn image/frame.
 */
export function applyForensicImageFilter(ctx, width, height, mode) {
  if (!mode || mode === "normal") return;
  const imgData = ctx.getImageData(0, 0, width, height);
  const src = imgData.data;
  const out = new Uint8ClampedArray(src.length);

  if (mode === "residual") {
    // High-pass Laplacian residual amplified for compression/splice seam visibility
    for (let y = 1; y < height - 1; y++) {
      for (let x = 1; x < width - 1; x++) {
        const idx = (y * width + x) * 4;
        for (let c = 0; c < 3; c++) {
          const center = src[idx + c] * 4;
          const neighbors =
            src[((y - 1) * width + x) * 4 + c] +
            src[((y + 1) * width + x) * 4 + c] +
            src[(y * width + (x - 1)) * 4 + c] +
            src[(y * width + (x + 1)) * 4 + c];
          const val = Math.min(255, Math.abs(center - neighbors) * 4.5);
          out[idx + c] = val;
        }
        out[idx + 3] = 255;
      }
    }
    imgData.data.set(out);
    ctx.putImageData(imgData, 0, 0);
    return;
  }

  if (mode === "heatmap") {
    for (let i = 0; i < src.length; i += 4) {
      const lum = (0.299 * src[i] + 0.587 * src[i + 1] + 0.114 * src[i + 2]) / 255;
      // Calibrated obsidian -> cyan -> amber -> crimson ramp
      let r = 0;
      let g = 0;
      let b = 0;
      if (lum < 0.35) {
        const t = lum / 0.35;
        r = 10;
        g = Math.round(30 + t * 140);
        b = Math.round(70 + t * 150);
      } else if (lum < 0.7) {
        const t = (lum - 0.35) / 0.35;
        r = Math.round(10 + t * 235);
        g = Math.round(170 - t * 20);
        b = Math.round(220 - t * 190);
      } else {
        const t = (lum - 0.7) / 0.3;
        r = Math.round(245);
        g = Math.round(150 - t * 110);
        b = Math.round(30 + t * 30);
      }
      out[i] = r;
      out[i + 1] = g;
      out[i + 2] = b;
      out[i + 3] = 255;
    }
    imgData.data.set(out);
    ctx.putImageData(imgData, 0, 0);
  }
}

export function renderViewportCanvas({
  canvas,
  uploadedImageEl,
  hasVideo,
  playheadSec,
  isPlaying,
  activeFakeAtPlayhead,
  filterMode,
  hoverPos,
}) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  const w = canvas.width;
  const h = canvas.height;

  ctx.clearRect(0, 0, w, h);

  if (!hasVideo) {
    if (uploadedImageEl && uploadedImageEl.complete && uploadedImageEl.naturalWidth > 0) {
      ctx.fillStyle = "#05080f";
      ctx.fillRect(0, 0, w, h);
      const scale = Math.min(w / uploadedImageEl.naturalWidth, h / uploadedImageEl.naturalHeight);
      const dw = uploadedImageEl.naturalWidth * scale;
      const dh = uploadedImageEl.naturalHeight * scale;
      const dx = (w - dw) / 2;
      const dy = (h - dh) / 2;
      ctx.drawImage(uploadedImageEl, dx, dy, dw, dh);
      applyForensicImageFilter(ctx, w, h, filterMode);
    } else {
      // Calibrated synthetic forensic reference stage
      const grad = ctx.createRadialGradient(w * 0.5, h * 0.45, 24, w * 0.5, h * 0.5, 240);
      grad.addColorStop(0, "#12203b");
      grad.addColorStop(1, "#05080f");
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, w, h);

      // Precision coordinate reticle grid
      ctx.strokeStyle = "rgba(59, 130, 246, 0.08)";
      ctx.lineWidth = 1;
      for (let gx = 40; gx < w; gx += 40) {
        ctx.beginPath();
        ctx.moveTo(gx, 0);
        ctx.lineTo(gx, h);
        ctx.stroke();
      }
      for (let gy = 40; gy < h; gy += 40) {
        ctx.beginPath();
        ctx.moveTo(0, gy);
        ctx.lineTo(w, gy);
        ctx.stroke();
      }

      const headX = w * 0.5 + Math.sin(playheadSec * 1.6) * 8;
      const headY = h * 0.46 + Math.cos(playheadSec * 2.1) * 3;
      ctx.strokeStyle = "#3b82f6";
      ctx.lineWidth = 1.75;
      ctx.beginPath();
      ctx.ellipse(headX, headY, 50, 64, 0, 0, Math.PI * 2);
      ctx.stroke();

      // Landmark alignment markers
      ctx.fillStyle = "#93c5fd";
      ctx.fillRect(headX - 22, headY - 14, 11, 4);
      ctx.fillRect(headX + 11, headY - 14, 11, 4);
      const mouthOpen = isPlaying ? Math.abs(Math.sin(playheadSec * 11)) * 10 + 3 : 4;
      ctx.strokeStyle = activeFakeAtPlayhead ? "#ef4444" : "#60a5fa";
      ctx.strokeRect(headX - 15, headY + 20, 30, mouthOpen);

      if (filterMode === "residual" || filterMode === "heatmap") {
        applyForensicImageFilter(ctx, w, h, filterMode);
      }

      ctx.fillStyle = "#94a3b8";
      ctx.font = '11px "IBM Plex Mono", ui-monospace, monospace';
      ctx.fillText(`FRAME #${String(Math.floor(playheadSec * 30)).padStart(4, "0")} · ${formatSec(playheadSec)}`, 12, 20);
    }
  }

  // Draw active anomaly bounding box on top of BOTH synthetic stream AND uploaded video/image!
  if (activeFakeAtPlayhead) {
    const box = activeFakeAtPlayhead.bbox || { x: 0.34, y: 0.22, w: 0.32, h: 0.44 };
    const bx = box.x * w;
    const by = box.y * h;
    const bw = box.w * w;
    const bh = box.h * h;

    ctx.save();
    ctx.strokeStyle = "#ef4444";
    ctx.lineWidth = 2;
    ctx.setLineDash([6, 4]);
    ctx.strokeRect(bx, by, bw, bh);
    ctx.setLineDash([]);

    // Corner brackets
    const cLen = 10;
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    ctx.moveTo(bx, by + cLen);
    ctx.lineTo(bx, by);
    ctx.lineTo(bx + cLen, by);
    ctx.moveTo(bx + bw - cLen, by);
    ctx.lineTo(bx + bw, by);
    ctx.lineTo(bx + bw, by + cLen);
    ctx.moveTo(bx, by + bh - cLen);
    ctx.lineTo(bx, by + bh);
    ctx.lineTo(bx + cLen, by + bh);
    ctx.moveTo(bx + bw - cLen, by + bh);
    ctx.lineTo(bx + bw, by + bh);
    ctx.lineTo(bx + bw, by + bh - cLen);
    ctx.stroke();

    const labelText = `FAKE (${Math.round(activeFakeAtPlayhead.calibrated_confidence * 100)}%) · ${activeFakeAtPlayhead.finding_id}`;
    ctx.font = 'bold 11px "IBM Plex Mono", ui-monospace, monospace';
    const labelW = Math.min(w - bx - 4, ctx.measureText(labelText).width + 14);
    const labelY = Math.max(4, by - 22);
    ctx.fillStyle = "rgba(185, 28, 28, 0.92)";
    ctx.fillRect(bx, labelY, labelW, 18);
    ctx.fillStyle = "#ffffff";
    ctx.fillText(labelText, bx + 6, labelY + 13);
    ctx.restore();
  }

  // Interactive coordinate crosshair probe
  if (hoverPos && hoverPos.x >= 0 && hoverPos.x <= w && hoverPos.y >= 0 && hoverPos.y <= h) {
    ctx.save();
    ctx.strokeStyle = "rgba(6, 182, 212, 0.5)";
    ctx.lineWidth = 1;
    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(hoverPos.x, 0);
    ctx.lineTo(hoverPos.x, h);
    ctx.moveTo(0, hoverPos.y);
    ctx.lineTo(w, hoverPos.y);
    ctx.stroke();
    ctx.setLineDash([]);

    const pxPct = ((hoverPos.x / w) * 100).toFixed(1);
    const pyPct = ((hoverPos.y / h) * 100).toFixed(1);
    const probeLabel = `X:${pxPct}% Y:${pyPct}%`;
    ctx.font = '10px "IBM Plex Mono", ui-monospace, monospace';
    const tw = ctx.measureText(probeLabel).width + 10;
    const lx = hoverPos.x + tw + 12 > w ? hoverPos.x - tw - 8 : hoverPos.x + 8;
    const ly = hoverPos.y - 22 < 4 ? hoverPos.y + 8 : hoverPos.y - 22;
    ctx.fillStyle = "rgba(7, 10, 16, 0.88)";
    ctx.fillRect(lx, ly, tw, 17);
    ctx.strokeStyle = "rgba(6, 182, 212, 0.65)";
    ctx.strokeRect(lx, ly, tw, 17);
    ctx.fillStyle = "#67e8f9";
    ctx.fillText(probeLabel, lx + 5, ly + 12);
    ctx.restore();
  }
}

export function renderEntropyCanvas({ canvas, evidenceItem, hoverBinIdx }) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;

  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "#05080f";
  ctx.fillRect(0, 0, w, h);

  const bins = evidenceItem?.metadata?.entropy_bins || [];
  const padL = 42;
  const padR = 16;
  const padT = 22;
  const padB = 28;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;

  // Grid lines (0, 2, 4, 6, 8 bits/byte)
  ctx.strokeStyle = "#172236";
  ctx.lineWidth = 1;
  ctx.font = '10px "IBM Plex Mono", ui-monospace, monospace';
  ctx.fillStyle = "#64748b";
  [0, 2, 4, 6, 8].forEach((val) => {
    const y = padT + plotH - (val / 8) * plotH;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(padL + plotW, y);
    ctx.stroke();
    ctx.fillText(`${val}.0`, 8, y + 3);
  });

  if (!bins.length) {
    ctx.fillStyle = "#64748b";
    ctx.font = '12px "IBM Plex Mono", ui-monospace, monospace';
    ctx.fillText("No entropy profile available for selected evidence.", padL + 16, h / 2);
    return;
  }

  // Highlight abrupt jumps >= 0.65 as splice anomaly zones
  const stepX = plotW / Math.max(1, bins.length - 1);
  for (let i = 1; i < bins.length; i++) {
    const jump = Math.abs(bins[i] - bins[i - 1]);
    if (jump >= 0.6) {
      const x1 = padL + (i - 1) * stepX;
      ctx.fillStyle = "rgba(239, 68, 68, 0.14)";
      ctx.fillRect(x1, padT, stepX, plotH);
    }
  }

  // Area fill under entropy curve
  ctx.beginPath();
  bins.forEach((b, i) => {
    const x = padL + i * stepX;
    const y = padT + plotH - (Math.max(0, Math.min(8, b)) / 8) * plotH;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.lineTo(padL + (bins.length - 1) * stepX, padT + plotH);
  ctx.lineTo(padL, padT + plotH);
  ctx.closePath();
  const areaGrad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
  areaGrad.addColorStop(0, "rgba(6, 182, 212, 0.28)");
  areaGrad.addColorStop(1, "rgba(6, 182, 212, 0.02)");
  ctx.fillStyle = areaGrad;
  ctx.fill();

  // Stroke line
  ctx.beginPath();
  bins.forEach((b, i) => {
    const x = padL + i * stepX;
    const y = padT + plotH - (Math.max(0, Math.min(8, b)) / 8) * plotH;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = "#06b6d4";
  ctx.lineWidth = 2;
  ctx.stroke();

  // Data nodes
  bins.forEach((b, i) => {
    const x = padL + i * stepX;
    const y = padT + plotH - (Math.max(0, Math.min(8, b)) / 8) * plotH;
    const jump = i > 0 ? Math.abs(b - bins[i - 1]) : 0;
    ctx.fillStyle = jump >= 0.6 ? "#ef4444" : i === hoverBinIdx ? "#f8fafc" : "#22d3ee";
    ctx.beginPath();
    ctx.arc(x, y, i === hoverBinIdx ? 4.5 : 2.5, 0, Math.PI * 2);
    ctx.fill();
  });

  // Hover readout
  if (typeof hoverBinIdx === "number" && hoverBinIdx >= 0 && hoverBinIdx < bins.length) {
    const x = padL + hoverBinIdx * stepX;
    const val = bins[hoverBinIdx];
    ctx.strokeStyle = "rgba(248, 250, 252, 0.45)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(x, padT);
    ctx.lineTo(x, padT + plotH);
    ctx.stroke();

    const txt = `WIN #${String(hoverBinIdx).padStart(2, "0")} · ${val.toFixed(2)} b/B`;
    ctx.font = '11px "IBM Plex Mono", ui-monospace, monospace';
    const tw = ctx.measureText(txt).width + 12;
    const tx = Math.min(w - tw - 8, Math.max(padL, x - tw / 2));
    ctx.fillStyle = "rgba(13, 19, 31, 0.95)";
    ctx.fillRect(tx, 4, tw, 17);
    ctx.strokeStyle = "#334155";
    ctx.strokeRect(tx, 4, tw, 17);
    ctx.fillStyle = "#e2e8f0";
    ctx.fillText(txt, tx + 6, 16);
  }

  ctx.fillStyle = "#64748b";
  ctx.font = '10px "IBM Plex Mono", ui-monospace, monospace';
  ctx.fillText("0% OFFSET", padL, h - 8);
  ctx.fillText("50% OFFSET", padL + plotW * 0.45, h - 8);
  ctx.fillText("100% EOF", padL + plotW - 52, h - 8);
}

export function drawTrackCanvas({
  canvasId,
  mode,
  indicators,
  activeFindingId,
  playheadSec,
  mediaDurationSec,
  liveFrequencyBins,
  isPlaying,
}) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;

  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "#05080f";
  ctx.fillRect(0, 0, w, h);

  ctx.strokeStyle = "#142036";
  ctx.lineWidth = 1;
  for (let x = 0; x < w; x += 64) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, h);
    ctx.stroke();
  }

  if (mode === "video") {
    const cellW = 38;
    for (let x = 8; x < w - 10; x += cellW) {
      const tAtCell = (x / w) * mediaDurationSec;
      const nearFake = indicators.some(
        (i) => isFakeIndicator(i) && Math.abs((i.timestamp_sec ?? 0) - tAtCell) < 0.9,
      );
      ctx.fillStyle = nearFake ? "rgba(239, 68, 68, 0.20)" : "rgba(37, 99, 235, 0.12)";
      ctx.fillRect(x, 26, cellW - 4, h - 36);
      ctx.strokeStyle = nearFake ? "rgba(239, 68, 68, 0.55)" : "#1c2b46";
      ctx.strokeRect(x, 26, cellW - 4, h - 36);
    }
  } else {
    const bars = 96;
    const step = w / bars;
    for (let i = 0; i < bars; i++) {
      const tAtBar = (i / bars) * mediaDurationSec;
      const nearFake = indicators.some(
        (ind) => isFakeIndicator(ind) && Math.abs((ind.timestamp_sec ?? 0) - tAtBar) < 0.9,
      );
      let amp;
      if (liveFrequencyBins && liveFrequencyBins.length > 0 && isPlaying) {
        const binIdx = Math.floor((i / bars) * liveFrequencyBins.length);
        amp = 8 + (liveFrequencyBins[binIdx] / 255) * (h - 38);
      } else {
        const phase = isPlaying ? playheadSec * 2.5 : 0;
        amp = 12 + Math.abs(Math.sin(i * 0.45 + phase) * Math.cos(i * 0.19)) * (h - 42);
      }
      ctx.fillStyle = nearFake ? "rgba(239, 68, 68, 0.72)" : "rgba(6, 182, 212, 0.52)";
      ctx.fillRect(i * step + 1, h - 10 - amp, Math.max(2, step - 2), amp);
    }
  }

  indicators.forEach((ind) => {
    const ratio = Math.max(0, Math.min(1, (ind.timestamp_sec ?? 0) / Math.max(0.1, mediaDurationSec)));
    const x = 14 + ratio * (w - 28);
    const fake = isFakeIndicator(ind);
    const isSel = ind.finding_id === activeFindingId;

    ctx.save();
    ctx.strokeStyle = fake ? "#ef4444" : "#10b981";
    ctx.lineWidth = isSel ? 3 : 1.75;
    ctx.beginPath();
    ctx.moveTo(x, 18);
    ctx.lineTo(x, h - 6);
    ctx.stroke();

    const tag = `${fake ? "FAKE" : "VERIFIED"} ${ind.finding_id}`;
    ctx.font = 'bold 10px "IBM Plex Mono", ui-monospace, monospace';
    const tagW = Math.max(76, ctx.measureText(tag).width + 10);
    const tagX = Math.min(x - 2, w - tagW - 4);
    ctx.fillStyle = fake ? "#dc2626" : "#059669";
    ctx.fillRect(tagX, 3, tagW, 15);
    ctx.fillStyle = "#ffffff";
    ctx.fillText(tag, tagX + 5, 14);
    ctx.restore();
  });

  const playX = 14 + Math.max(0, Math.min(1, playheadSec / Math.max(0.1, mediaDurationSec))) * (w - 28);
  ctx.strokeStyle = "#f8fafc";
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(playX, 0);
  ctx.lineTo(playX, h);
  ctx.stroke();
}
