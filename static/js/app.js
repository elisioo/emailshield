/* EmailShield frontend; all detection runs in Flask, not in the browser. */
(() => {
  "use strict";
  const $ = (selector) => document.querySelector(selector);
  const heading = $("#hero-title");
  const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const first = $(".heading-think");
  const last = $(".heading-click strong");
  let swapped = false;
  window.setInterval(() => {
    if (motion.matches || document.hidden) return;
    heading.classList.add("is-glitching");
    window.setTimeout(() => {
      swapped = !swapped;
      first.textContent = swapped ? "CLICK" : "THINK";
      last.textContent = swapped ? "THINK" : "CLICK";
    }, 120);
    window.setTimeout(() => heading.classList.remove("is-glitching"), 340);
  }, 4000);

  const tabs = [...document.querySelectorAll(".mode-tab")];
  const fileInput = $("#email-file");
  const dropZone = $("#drop-zone");
  const emailText = $("#email-text");
  const scanButton = $("#scan-button");
  const scanLoader = $("#scan-loader");
  const message = $("#form-message");
  const resultsSection = $("#results");
  let activeMode = "upload";
  let chosenFile = null;
  let currentReport = null;
  const MAX_FILE_BYTES = 2 * 1024 * 1024;
  const MAX_PASTE_CHARS = 200000;

  const demoEmail = `From: "Accounts Payable" <accounts@vendor-example.com>
Reply-To: urgent-payment@invoice-confirm.example
To: customer@example.org
Subject: Urgent: update payment details today
MIME-Version: 1.0
Authentication-Results: mail.example.org; spf=fail smtp.mailfrom=vendor-example.com
Content-Type: text/html; charset="utf-8"

<p>Urgent action required: We changed our bank account.</p>
<p>Please make a wire transfer using new payment details.</p>
<p>Verify your account <a href="http://192.0.2.5/login">https://vendor-example.com/login</a>.</p>`;

  function notice(text, good = false) {
    message.textContent = text;
    message.classList.toggle("ok", good);
  }
  function setMode(mode) {
    activeMode = mode;
    tabs.forEach((tab) => {
      const selected = tab.dataset.mode === mode;
      tab.classList.toggle("active", selected);
      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
    $("#upload-panel").hidden = mode !== "upload";
    $("#paste-panel").hidden = mode !== "paste";
    notice("");
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => setMode(tab.dataset.mode));
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
      event.preventDefault();
      const next = tabs[(index + (event.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
      setMode(next.dataset.mode);
      next.focus();
    });
  });
  function useFile(file) {
    if (!file) return;
    if (!/\.(eml|txt)$/i.test(file.name)) {
      chosenFile = null;
      notice("Use an .eml or .txt file.");
      return;
    }
    if (!file.size || file.size > MAX_FILE_BYTES) {
      chosenFile = null;
      notice("Choose a nonempty email no larger than 2 MB.");
      return;
    }
    chosenFile = file;
    $("#file-name").textContent = file.name;
    $("#file-help").textContent = `${(file.size / 1024).toFixed(1)} KB · ready to scan`;
    setMode("upload");
    notice("File selected. Select SCAN NOW to analyze it with Flask.", true);
  }
  dropZone.addEventListener("click", () => fileInput.click());
  dropZone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      fileInput.click();
    }
  });
  fileInput.addEventListener("change", () => useFile(fileInput.files?.[0]));
  ["dragenter", "dragover"].forEach((type) => dropZone.addEventListener(type, (event) => {
    event.preventDefault();
    dropZone.classList.add("drag-over");
  }));
  ["dragleave", "drop"].forEach((type) => dropZone.addEventListener(type, (event) => {
    event.preventDefault();
    dropZone.classList.remove("drag-over");
  }));
  dropZone.addEventListener("drop", (event) => useFile(event.dataTransfer?.files?.[0]));
  $("#load-sample").addEventListener("click", () => {
    emailText.value = demoEmail;
    notice("Fictional sample loaded. Press SCAN NOW.", true);
  });

  function makeText(parent, tag, value, className = "") {
    const element = document.createElement(tag);
    if (className) element.className = className;
    element.textContent = String(value ?? "");
    parent.appendChild(element);
    return element;
  }
  function simpleRows(target, data, blank) {
    target.replaceChildren();
    if (!data.length) {
      makeText(target, "div", blank, "record-item");
      return;
    }
    data.forEach((item) => {
      const row = makeText(target, "div", item.main, "record-item");
      if (item.sub) makeText(row, "small", item.sub);
    });
  }
  function renderReport(report) {
    const labels = {
      high: ["Several warning signs", "High heuristic risk. Do not act on this message until you independently verify the sender and request."],
      medium: ["Review before trusting", "Some suspicious indicators were found. Verify the message independently."],
      low: ["Few indicators found", "No strong match in these limited checks. This email has NOT been verified safe."],
    };
    $("#risk-number").textContent = String(report.score);
    $("#risk-dial").style.setProperty("--amount", `${report.score}%`);
    $("#risk-label").textContent = labels[report.level][0];
    $("#risk-description").textContent = labels[report.level][1];

    const meta = $("#report-metadata");
    meta.replaceChildren();
    for (const [label, value] of [
      ["SOURCE", report.source],
      ["SUBJECT", report.subject],
      ["FROM", report.from],
      ["REPLY-TO", report.reply],
      ["LINKS / ATTACHMENTS", `${report.links.length} / ${report.attachments.length}`],
    ]) {
      const item = makeText(meta, "div", "", "metadata-item");
      makeText(item, "small", label);
      makeText(item, "strong", value);
    }
    $("#finding-count").textContent = `${report.findings.length} FLAG${report.findings.length === 1 ? "" : "S"}`;
    const list = $("#findings-list");
    list.replaceChildren();
    if (!report.findings.length) {
      const entry = makeText(list, "div", "", "finding");
      makeText(entry, "span", "INFO", "finding-level low");
      const text = makeText(entry, "div", "");
      makeText(text, "h4", "No rule matched");
      makeText(text, "p", "A low risk score does not establish that this message is safe.");
    }
    report.findings.forEach((finding) => {
      const entry = makeText(list, "div", "", "finding");
      makeText(entry, "span", finding.level.toUpperCase(), `finding-level ${finding.level}`);
      const text = makeText(entry, "div", "");
      makeText(text, "h4", finding.title);
      makeText(text, "p", finding.detail);
      if (finding.evidence) makeText(text, "p", `Evidence: ${finding.evidence} (+${finding.weight} points)`, "finding-evidence");
    });
    const recommendations = $("#recommendations-list");
    recommendations.replaceChildren();
    report.recommendations.forEach((action) => makeText(recommendations, "li", action));
    simpleRows($("#attachment-details"), report.attachments.map((a) => ({
      main: a.filename, sub: `${a.content_type} · ${a.size_bytes} bytes · ${a.extension || "no extension"}`
    })), "No attachments identified from MIME metadata.");
    simpleRows($("#url-details"), report.links.map((link) => ({
      main: link.host, sub: link.label ? `Shown as: ${link.label}` : "Found in message; URL not visited"
    })), "No web URLs identified in the readable email body.");
    simpleRows($("#auth-claims"), report.authentication_claims.map((claim) => ({
      main: `${claim.method}: ${claim.reported_result}`, sub: "Unverified claim copied from the supplied header"
    })), "No Authentication-Results claims found. This does not mean authentication passed.");
    resultsSection.hidden = false;
    resultsSection.scrollIntoView({behavior: motion.matches ? "auto" : "smooth", block: "start"});
  }

  scanButton.addEventListener("click", async () => {
    const payload = new FormData();
    payload.append("mode", activeMode);
    if (activeMode === "upload") {
      if (!chosenFile) {
        notice("Choose an .eml or .txt file, or switch to PASTE EMAIL.");
        dropZone.focus();
        return;
      }
      payload.append("file", chosenFile, chosenFile.name);
    } else {
      const raw = emailText.value.trim();
      if (!raw) {
        notice("Paste the message first or try the fictional sample.");
        emailText.focus();
        return;
      }
      if (raw.length > MAX_PASTE_CHARS) {
        notice("Text is too long. Maximum 200,000 characters.");
        return;
      }
      payload.append("email_text", raw);
    }
    scanButton.disabled = true;
    scanLoader.hidden = false;
    $("#scan").setAttribute("aria-busy", "true");
    scanButton.querySelector("span").textContent = "ANALYZING…";
    notice("Analyzing using the Flask server. No email is saved.");
    try {
      const response = await fetch("/api/analyze", {
        method: "POST", body: payload, cache: "no-store",
        headers: { "Accept": "application/json" },
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Unable to scan that email.");
      currentReport = result;
      renderReport(result);
      notice("Analysis complete. See the report below.", true);
    } catch (error) {
      notice(error instanceof TypeError ? "Could not reach Flask. Start the server with python app.py." : error.message);
    } finally {
      scanLoader.hidden = true;
      $("#scan").removeAttribute("aria-busy");
      scanButton.disabled = false;
      scanButton.querySelector("span").textContent = "SCAN NOW";
    }
  });
  $("#scan-another").addEventListener("click", () => {
    resultsSection.hidden = true;
    currentReport = null;
    $("#scan").scrollIntoView({behavior: motion.matches ? "auto" : "smooth", block: "center"});
  });
  $("#download-report").addEventListener("click", () => {
    if (!currentReport) return;
    const r = currentReport;
    const lines = [
      "EMAILSHIELD — EMAIL REVIEW REPORT", "=================================",
      `Generated: ${new Date().toLocaleString()}`,
      `Source: ${r.source}`, `Subject: ${r.subject}`,
      `From: ${r.from}`, `Reply-To: ${r.reply}`, `Return-Path: ${r.return_path}`,
      `Links found: ${r.links.length}`, `Attachments found: ${r.attachments.length}`,
      `Heuristic risk score: ${r.score}/100 (${r.level.toUpperCase()})`, "",
      "FINDINGS", "--------",
      ...(r.findings.length ? r.findings.flatMap((f, i) => [
        `${i + 1}. [${f.level.toUpperCase()}] ${f.title} (+${f.weight} points)`,
        `   ${f.detail}`, `   Evidence: ${f.evidence}`]) : ["No checked rules matched."]),
      "", "RECOMMENDED ACTIONS", "-------------------",
      ...r.recommendations.map((v, i) => `${i + 1}. ${v}`),
      "", "ATTACHMENT METADATA", "-------------------",
      ...(r.attachments.length ? r.attachments.map((a) => `${a.filename} | ${a.content_type} | ${a.size_bytes} bytes`) : ["No attachment metadata detected."]),
      "", "SUBMITTED AUTHENTICATION-RESULTS (UNVERIFIED)", "----------------------------------------------",
      ...(r.authentication_claims.length ? r.authentication_claims.map((a) => `${a.method}: ${a.reported_result}`) : ["None supplied."]),
      "", "LIMITATIONS", "-----------", ...r.limitations,
    ];
    const blob = new Blob([lines.join("\n")], {type:"text/plain;charset=utf-8"});
    const href = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = href;
    a.download = "emailshield-review-report.txt";
    a.click();
    window.setTimeout(() => URL.revokeObjectURL(href), 2000);
  });
})();
