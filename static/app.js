const form = document.querySelector("#analyzeForm");
const fileInput = document.querySelector("#fileInput");
const fileLabel = document.querySelector("#fileLabel");
const dropZone = document.querySelector("#dropZone");
const resultsPanel = document.querySelector("#resultsPanel");
const appStatus = document.querySelector("#appStatus");
const submitButton = document.querySelector("#submitButton");
const resultTemplate = document.querySelector("#resultTemplate");
const autoTools = document.querySelector("#autoTools");
const manualTools = document.querySelector("#manualTools");

const severityRank = { info: 0, low: 1, medium: 2, high: 3, error: 2 };
const pdfExtensions = new Set(["pdf"]);
const officeExtensions = new Set([
  "doc", "docm", "dot", "dotm", "xls", "xlsm", "xlsb", "xlt", "xltm",
  "ppt", "pptm", "pot", "potm", "rtf", "xml", "mht", "mhtml", "zip",
]);
const pdfTools = ["pdf_static"];
const officeTools = ["oleid", "olevba", "mraptor", "objects"];
const allTools = ["oleid", "olevba", "mraptor", "objects", "pdf_static"];

fileInput.addEventListener("change", () => {
  updateSelectedFiles();
});

autoTools.addEventListener("change", () => {
  updateAutoToolState();
  updateSelectedFiles();
});

for (const eventName of ["dragenter", "dragover"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("drag-over");
  });
}

for (const eventName of ["dragleave", "drop"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("drag-over");
  });
}

dropZone.addEventListener("drop", (event) => {
  const files = [...event.dataTransfer.files];
  if (!files.length) return;
  const transfer = new DataTransfer();
  for (const file of files) {
    transfer.items.add(file);
  }
  fileInput.files = transfer.files;
  updateSelectedFiles();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const files = [...fileInput.files];
  if (!files.length) return;

  const checkedTools = [...document.querySelectorAll("input[name='tool']:checked")].map(
    (input) => input.value,
  );

  const data = new FormData();
  for (const file of files) {
    data.append("files", file);
  }
  data.append("tools", checkedTools.join(","));
  data.append("auto_tools", autoTools.checked);
  data.append("zip_password", document.querySelector("#zipPassword").value);
  data.append("office_password", document.querySelector("#officePassword").value);
  data.append("include_macro_source", document.querySelector("#includeMacroSource").checked);
  data.append("include_decoded_strings", document.querySelector("#includeDecoded").checked);

  setBusy(true);
  try {
    const response = await fetch("/api/analyze/bulk", { method: "POST", body: data });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || "Analysis failed");
    }
    renderTriage(payload);
    appStatus.textContent = "Complete";
  } catch (error) {
    resultsPanel.innerHTML = `
      <div class="empty-state">
        <div class="empty-mark">ERR</div>
        <h2>Analysis failed</h2>
        <p>${escapeHtml(error.message)}</p>
      </div>
    `;
    appStatus.textContent = "Error";
  } finally {
    setBusy(false);
  }
});

function updateAutoToolState() {
  manualTools.classList.toggle("disabled", autoTools.checked);
  for (const input of document.querySelectorAll("input[name='tool']")) {
    input.disabled = autoTools.checked;
  }
}

function updateSelectedFiles() {
  const files = [...fileInput.files];
  if (!files.length) {
    fileLabel.textContent = "Choose documents";
    if (autoTools.checked) setManualToolChecks(allTools);
    return;
  }
  fileLabel.textContent = files.length === 1 ? files[0].name : `${files.length} files selected`;
  if (autoTools.checked) {
    const selected = new Set(files.flatMap((file) => toolsForFile(file.name)));
    setManualToolChecks([...selected]);
  }
}

function extensionFor(name) {
  const last = String(name || "").toLowerCase().split(".").pop();
  return last === String(name || "").toLowerCase() ? "" : last;
}

function toolsForFile(name) {
  const ext = extensionFor(name);
  if (pdfExtensions.has(ext)) return pdfTools;
  if (officeExtensions.has(ext)) return officeTools;
  return allTools;
}

function setManualToolChecks(keys) {
  const selected = new Set(keys);
  for (const input of document.querySelectorAll("input[name='tool']")) {
    input.checked = selected.has(input.value);
  }
}

function setBusy(isBusy) {
  submitButton.disabled = isBusy;
  submitButton.textContent = isBusy ? "Analyzing..." : "Analyze selected documents";
  appStatus.textContent = isBusy ? "Running" : appStatus.textContent;
}

function renderTriage(payload) {
  resultsPanel.innerHTML = "";
  const reports = payload.results || (payload.file ? [payload] : []);
  const header = document.createElement("header");
  header.className = "report-header triage-header";
  header.innerHTML = `
    <div class="risk-row">
      <div>
        <h2>Triage view</h2>
        <p>${escapeHtml(payload.summary || `Analyzed ${reports.length} file(s).`)}</p>
      </div>
      <span class="risk-badge risk-${payload.risk || "info"}">${escapeHtml(payload.risk || "info")}</span>
    </div>
    <div class="metadata">
      <span>${reports.length} file(s)</span>
      <span>Tool v${escapeHtml(payload.app_version || "1.1")}</span>
      <span>${autoTools.checked ? "Auto analyzer selection" : "Manual analyzer selection"}</span>
    </div>
  `;
  resultsPanel.appendChild(header);

  const grid = document.createElement("section");
  grid.className = "triage-grid";
  for (const report of reports) {
    const card = document.createElement("article");
    card.className = "triage-card";
    const selected = report.selected_tools?.length ? report.selected_tools.join(", ") : "default";
    card.innerHTML = `
      <div>
        <strong>${escapeHtml(report.file.original_name)}</strong>
        <p>${escapeHtml(report.summary)}</p>
      </div>
      <span class="risk-badge risk-${report.risk}">${escapeHtml(report.risk)}</span>
      <small>${formatBytes(report.file.size)} · ${escapeHtml(report.file.content_type || "Unknown type")} · ${escapeHtml(selected)}</small>
    `;
    card.addEventListener("click", () => {
      document.querySelector(`[data-report-id="${reportId(report)}"]`)?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
    grid.appendChild(card);
  }
  resultsPanel.appendChild(grid);

  for (const report of reports) {
    const wrap = document.createElement("section");
    wrap.className = "file-report";
    wrap.dataset.reportId = reportId(report);
    wrap.appendChild(renderReportHeader(report));
    for (const result of report.results) {
      wrap.appendChild(renderResult(result));
    }
    resultsPanel.appendChild(wrap);
  }
}

function reportId(report) {
  return `${report.file.stored_name || report.file.original_name}`.replace(/[^A-Za-z0-9_-]+/g, "_");
}

function renderReportHeader(report) {
  const header = document.createElement("header");
  header.className = "report-header file-report-header";
  const selected = report.selected_tools?.length ? report.selected_tools.join(", ") : "default";
  header.innerHTML = `
    <div class="risk-row">
      <div>
        <h2>${escapeHtml(report.file.original_name)}</h2>
        <p>${escapeHtml(report.summary)}</p>
      </div>
      <span class="risk-badge risk-${report.risk}">${escapeHtml(report.risk)}</span>
    </div>
    <div class="metadata">
      <span>${formatBytes(report.file.size)}</span>
      <span>${escapeHtml(report.file.content_type || "Unknown type")}</span>
      <span>${report.results.length} analyzers</span>
      <span>${escapeHtml(selected)}</span>
      <span>Tool v${escapeHtml(report.app_version || "1.1")}</span>
    </div>
  `;
  return header;
}

function renderReport(report) {
  resultsPanel.innerHTML = "";
  const header = renderReportHeader(report);
  resultsPanel.appendChild(header);

  for (const result of report.results) {
    resultsPanel.appendChild(renderResult(result));
  }
}

function renderResult(result) {
  const fragment = resultTemplate.content.cloneNode(true);
  const block = fragment.querySelector(".result-block");
  fragment.querySelector(".result-title").textContent = result.label;
  fragment.querySelector(".result-summary").textContent = result.summary;
  fragment.querySelector(".result-count").textContent = `${result.findings.length} findings`;
  const body = fragment.querySelector(".result-body");

  if (result.findings.length) {
    const list = document.createElement("div");
    list.className = "finding-list";
    for (const finding of [...result.findings].sort(bySeverity)) {
      const item = document.createElement("div");
      item.className = `finding ${finding.severity}`;
      item.innerHTML = `
        <strong>${escapeHtml(finding.title)}</strong>
        <span>${escapeHtml(finding.detail || String(finding.value ?? ""))}</span>
      `;
      list.appendChild(item);
    }
    body.appendChild(list);
  }

  if (result.data?.indicators?.length) {
    body.appendChild(renderTable(result.data.indicators, ["name", "value", "risk", "description"]));
  }

  if (result.data?.file) {
    body.appendChild(renderKeyValueTable(result.data.file, "File"));
  }

  if (result.data?.structure?.length) {
    body.appendChild(renderTable(result.data.structure, ["name", "count"]));
  }

  if (result.data?.keyword_counts?.length) {
    body.appendChild(renderTable(result.data.keyword_counts, ["keyword", "count", "obfuscated"]));
  }

  if (result.data?.open_action?.present) {
    body.appendChild(renderOpenAction(result.data.open_action));
  }

  if (result.data?.uris?.length) {
    body.appendChild(renderTable(result.data.uris, ["uri"]));
  }

  if (result.data?.metadata?.length) {
    body.appendChild(renderTable(result.data.metadata, ["field", "value"]));
  }

  if (result.data?.embedded_files?.length) {
    body.appendChild(renderEmbeddedFiles(result.data.embedded_files));
  }

  if (result.data?.pymupdf) {
    body.appendChild(renderPyMuPdf(result.data.pymupdf));
  }

  if (result.data?.analysis?.length) {
    body.appendChild(renderTable(result.data.analysis, ["type", "keyword", "description", "severity"]));
  }

  if (result.data?.macros?.length) {
    body.appendChild(renderMacros(result.data.macros));
  }

  if (result.raw_output) {
    const pre = document.createElement("pre");
    pre.textContent = result.raw_output;
    body.appendChild(pre);
  }

  if (!body.children.length) {
    const none = document.createElement("p");
    none.className = "metadata";
    none.textContent = "No detailed output for this analyzer.";
    body.appendChild(none);
  }

  fragment.querySelector(".result-heading").addEventListener("click", () => {
    block.classList.toggle("collapsed");
  });

  return fragment;
}

function renderTable(rows, columns) {
  const wrap = document.createElement("div");
  wrap.className = "table-wrap";
  const table = document.createElement("table");
  table.innerHTML = `
    <thead><tr>${columns.map((column) => `<th>${escapeHtml(column)}</th>`).join("")}</tr></thead>
    <tbody></tbody>
  `;
  const body = table.querySelector("tbody");
  for (const row of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = columns.map((column) => `<td>${escapeHtml(formatValue(row[column]))}</td>`).join("");
    body.appendChild(tr);
  }
  wrap.appendChild(table);
  return wrap;
}

function renderKeyValueTable(values, title) {
  const rows = Object.entries(values).map(([key, value]) => ({ key, value }));
  const wrap = document.createElement("section");
  wrap.className = "detail-section";
  const heading = document.createElement("h3");
  heading.textContent = title;
  wrap.append(heading, renderTable(rows, ["key", "value"]));
  return wrap;
}

function renderOpenAction(details) {
  const wrap = document.createElement("section");
  wrap.className = "detail-section";
  const heading = document.createElement("h3");
  heading.textContent = "OpenAction details";
  wrap.appendChild(heading);

  const summary = {
    present: details.present,
    kind: details.kind,
    action_type: details.action_type,
    risk: details.risk,
    target_page: details.target_page,
    fit_mode: details.fit_mode,
    summary: details.summary,
    error: details.error,
  };
  wrap.appendChild(renderTable(
    Object.entries(summary)
      .filter(([, value]) => value !== undefined && value !== null && value !== "")
      .map(([key, value]) => ({ key, value })),
    ["key", "value"],
  ));

  if (details.raw !== undefined) {
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(details.raw, null, 2);
    wrap.appendChild(pre);
  }
  return wrap;
}

function renderEmbeddedFiles(files) {
  const wrap = document.createElement("section");
  wrap.className = "detail-section";
  const heading = document.createElement("h3");
  heading.textContent = "Embedded files analysis";
  wrap.appendChild(heading);
  wrap.appendChild(renderTable(files, [
    "index",
    "name",
    "size",
    "declared_size",
    "magic",
    "entropy",
    "risk",
    "risk_reason",
    "md5",
    "sha1",
    "sha256",
    "first_bytes_hex",
    "printable_preview",
    "description",
  ]));
  return wrap;
}

function renderPyMuPdf(details) {
  const wrap = document.createElement("section");
  wrap.className = "detail-section";
  const heading = document.createElement("h3");
  heading.textContent = "PyMuPDF";
  wrap.appendChild(heading);

  const summary = {
    available: details.available,
    page_count: details.page_count,
    is_encrypted: details.is_encrypted,
    needs_password: details.needs_password,
    authenticated: details.authenticated,
    error: details.error,
  };
  wrap.appendChild(renderTable(
    Object.entries(summary)
      .filter(([, value]) => value !== undefined && value !== null && value !== "")
      .map(([key, value]) => ({ key, value })),
    ["key", "value"],
  ));

  if (details.metadata && Object.keys(details.metadata).length) {
    wrap.appendChild(renderKeyValueTable(details.metadata, "PyMuPDF metadata"));
  }
  return wrap;
}

function renderMacros(macros) {
  const grid = document.createElement("div");
  grid.className = "macro-grid";

  const toolbar = document.createElement("div");
  toolbar.className = "macro-toolbar";
  const downloadAll = document.createElement("button");
  downloadAll.className = "tool-button";
  downloadAll.type = "button";
  downloadAll.textContent = "Download all macro source";
  downloadAll.addEventListener("click", () => {
    const source = macros.map(formatMacroSource).join("\n\n");
    downloadText("extracted-macros.bas", source);
  });
  toolbar.appendChild(downloadAll);
  grid.appendChild(toolbar);

  for (const macro of macros) {
    const item = document.createElement("section");
    item.className = "macro-item";
    const header = document.createElement("div");
    header.className = "macro-header";
    const title = document.createElement("h3");
    title.textContent = macro.module || macro.stream_path || "Macro module";
    const downloadOne = document.createElement("button");
    downloadOne.className = "tool-button compact";
    downloadOne.type = "button";
    downloadOne.textContent = "Download";
    downloadOne.addEventListener("click", () => {
      downloadText(macroFilename(macro), formatMacroSource(macro));
    });
    header.append(title, downloadOne);
    const pre = document.createElement("pre");
    pre.textContent = macro.code || "";
    item.append(header, pre);
    grid.appendChild(item);
  }
  return grid;
}

function formatMacroSource(macro) {
  const moduleName = macro.module || macro.stream_path || "Macro module";
  const container = macro.container || "";
  return [
    `' Container: ${container}`,
    `' Module: ${moduleName}`,
    "",
    macro.code || "",
  ].join("\n");
}

function macroFilename(macro) {
  const name = macro.module || macro.stream_path || macro.container || "macro";
  const cleaned = String(name).split(/[\\/]/).pop().replace(/[^A-Za-z0-9._-]+/g, "_") || "macro";
  return cleaned.toLowerCase().endsWith(".bas") ? cleaned : `${cleaned}.bas`;
}

function downloadText(filename, content) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function bySeverity(a, b) {
  return (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0);
}

function formatValue(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

updateAutoToolState();
updateSelectedFiles();
