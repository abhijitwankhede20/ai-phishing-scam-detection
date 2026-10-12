(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const setText = (id, value) => {
    const el = $(id);
    if (el) el.textContent = value === null || value === undefined || value === "" ? "Not available" : String(value);
  };
  const showError = (id, message) => {
    const el = $(id);
    if (!el) return;
    el.textContent = message;
    el.classList.remove("hidden");
  };
  const setLoading = (loadingId, button, isLoading, label) => {
    const loading = $(loadingId);
    if (loading) loading.classList.toggle("hidden", !isLoading);
    if (button) {
      button.disabled = isLoading;
      button.dataset.originalText ||= button.textContent.trim();
      button.textContent = isLoading ? label : button.dataset.originalText;
    }
  };
  const safeNumber = (value) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  };
  const addReasons = (listId, reasons) => {
    const list = $(listId);
    if (!list) return;
    list.replaceChildren();
    const values = Array.isArray(reasons) ? reasons : [];
    if (!values.length) {
      const item = document.createElement("li");
      item.className = "finding-empty";
      item.textContent = "No specific warning reasons were returned by this detector.";
      list.appendChild(item);
      return;
    }
    values.forEach(reason => {
      const item = document.createElement("li");
      item.className = "finding-item";
      const mark = document.createElement("span");
      mark.className = "finding-mark";
      mark.textContent = "!";
      mark.setAttribute("aria-hidden", "true");
      const text = document.createElement("span");
      text.textContent = String(reason);
      item.append(mark, text);
      list.appendChild(item);
    });
  };
  const setProgress = (barId, value, containerSelector) => {
    const bar = $(barId);
    if (!bar) return;
    const score = safeNumber(value);
    const valid = score !== null && score >= 0 && score <= 100;
    bar.style.width = valid ? `${score}%` : "0%";
    const container = bar.closest('[role="progressbar"]');
    if (container) container.setAttribute("aria-valuenow", valid ? String(score) : "0");
  };
  const styleVerdict = (panelId, badgeId, style, title) => {
    const panel = $(panelId);
    const badge = $(badgeId);
    if (panel) panel.className = `verdict-panel ${style}`;
    if (badge) {
      badge.className = `status-badge ${style}`;
      badge.textContent = title;
    }
  };
  const renderActionList = (listId, actions) => {
    const list = $(listId);
    if (!list) return;
    list.replaceChildren();
    actions.forEach(action => {
      const item = document.createElement("li");
      item.textContent = action;
      list.appendChild(item);
    });
  };

  // Website URL scanner
  const websiteForm = $("scan-form");
  if (websiteForm) {
    const button = $("scan-button");
    websiteForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submittedUrl = $("url-input")?.value.trim() || "";
      if (!submittedUrl) return;
      $("error-box")?.classList.add("hidden");
      $("report")?.classList.add("hidden");
      setLoading("loading", button, true, "Analyzing…");
      try {
        const response = await fetch("/check-url", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: submittedUrl })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The website could not be analyzed.");
        renderWebsiteReport(data, submittedUrl);
      } catch (error) {
        showError("error-box", error.message || "Could not connect to the API. Make sure the FastAPI server is running.");
      } finally {
        setLoading("loading", button, false, "Analyzing…");
      }
    });
    $("print-button")?.addEventListener("click", () => window.print());
  }

  function renderWebsiteReport(data, submittedUrl) {
    const rawVerdict = String(data.result ?? data.prediction ?? "UNKNOWN").toUpperCase();
    const phishing = rawVerdict.includes("PHISH");
    const suspicious = !phishing && (rawVerdict.includes("SUSPICIOUS") || rawVerdict.includes("RISK"));
    const style = phishing ? "phishing" : suspicious ? "suspicious" : "legitimate";
    const verdict = phishing ? "POTENTIAL PHISHING WEBSITE" : suspicious ? "SUSPICIOUS WEBSITE" : rawVerdict.includes("UNKNOWN") ? "RESULT NEEDS REVIEW" : "NO STRONG WARNING DETECTED";
    const description = phishing
      ? "The configured detector classified this URL as potentially phishing. Avoid entering sensitive information until independently verified."
      : suspicious
        ? "The detector returned warning signals. Review the findings and verify the domain before continuing."
        : "The configured detector did not return a strong phishing warning. This does not guarantee that the website is safe.";
    styleVerdict("verdict-panel", "status-badge", style, verdict);
    setText("verdict-title", verdict);
    setText("prediction-description", description);
    const icon = $("verdict-icon");
    if (icon) icon.textContent = phishing ? "!" : suspicious ? "⚠" : "✓";

    const phishScore = safeNumber(data.phishing_probability);
    setText("phishing-probability", phishScore === null ? "Not available" : `${phishScore.toFixed(2)}%`);
    setProgress("probability-bar", phishScore);
    setText("risk-points", data.risk_points ?? "Not available");
    setText("risk-description", Array.isArray(data.reasons) && data.reasons.length ? `${data.reasons.length} configured warning indicator(s) returned.` : "No specific structural warnings returned.");
    setText("hostname-metric", data.hostname || "Not available");
    setText("hostname", data.hostname || "Not available");
    setText("submitted-url", submittedUrl);
    setText("normalized-url", data.normalized_url || "Not available");
    setText("report-time", `Scanned on ${new Date().toLocaleString()}`);
    addReasons("reasons-list", data.reasons);

    const actionPanel = $("action-panel");
    if (actionPanel) actionPanel.className = `action-panel ${style}`;
    setText("action-title", phishing ? "Do not proceed yet" : suspicious ? "Verify before continuing" : "Continue with caution");
    setText("action-copy", phishing ? "Treat this URL as potentially dangerous until you confirm it through a trusted source." : "A detector result alone cannot confirm whether a website is trustworthy.");
    renderActionList("action-list", phishing
      ? ["Do not enter passwords or payment details.", "Open the official website by typing its known address yourself.", "Report the suspicious link if appropriate."]
      : ["Check the domain spelling carefully.", "Verify unexpected links through a trusted source.", "Avoid entering sensitive information if anything seems unusual."]);
    $("report")?.classList.remove("hidden");
    $("report")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // Combined email scanner
  const emailForm = $("email-form");
  if (emailForm) {
    const button = $("email-scan-button");
    emailForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const sender_email = $("sender-input")?.value.trim() || "";
      const subject = $("subject-input")?.value.trim() || "";
      const body = $("email-body-input")?.value.trim() || "";
      if (!subject && !body) {
        showError("email-error-box", "Enter an email subject or email body.");
        return;
      }
      $("email-error-box")?.classList.add("hidden");
      $("email-report")?.classList.add("hidden");
      setLoading("email-loading", button, true, "Analyzing…");
      try {
        const response = await fetch("/check-email-combined", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sender_email, subject, body })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The email could not be analyzed.");
        renderEmailReport(data);
      } catch (error) {
        showError("email-error-box", error.message || "Could not connect to the API. Make sure the FastAPI server is running.");
      } finally {
        setLoading("email-loading", button, false, "Analyzing…");
      }
    });
    $("email-print-button")?.addEventListener("click", () => window.print());
  }

  function renderEmailReport(data) {
    const rule = data.rule_based || {};
    const ml = data.machine_learning || {};
    const rulePrediction = String(rule.prediction || "UNKNOWN").toUpperCase();
    const mlPrediction = String(ml.prediction || "UNKNOWN").toUpperCase();
    const ruleRisk = safeNumber(rule.risk_score);
    const mlScore = safeNumber(ml.phishing_model_score);
    const ruleHigh = rulePrediction.includes("PHISHING");
    const ruleSuspicious = rulePrediction === "SUSPICIOUS";
    const mlHigh = mlPrediction.includes("PHISHING");
    let style = "suspicious";
    let verdict = "REVIEW REQUIRED";
    let description = "Review both detector outputs before trusting this email.";
    let actionTitle = "Verify this email";
    let actionCopy = "Do not follow unexpected links or requests until independently verified.";
    let actions = ["Verify the sender through a separate trusted channel.", "Do not enter passwords or payment details through email links.", "Avoid opening unexpected attachments."];

    if (ruleHigh || mlHigh) {
      style = "phishing";
      verdict = "POTENTIAL PHISHING / SCAM";
      description = "At least one detector classified this email as high risk.";
      actionTitle = "Do not act on this email yet";
      actionCopy = "Treat this message as potentially dangerous until verified.";
    } else if (rulePrediction === "LOWER RISK" && mlPrediction === "SAFE") {
      style = "legitimate";
      verdict = "NO STRONG WARNING DETECTED";
      description = "Both detectors returned lower-risk classifications. This does not guarantee safety.";
      actionTitle = "Continue with caution";
      actionCopy = "A low-risk result cannot prove that the sender or message is trustworthy.";
      actions = ["Check the sender address carefully.", "Verify unexpected requests independently.", "Avoid sharing sensitive information unnecessarily."];
    } else if (ruleSuspicious || mlPrediction !== "SAFE") {
      verdict = "SUSPICIOUS — REVIEW";
      description = "One or both detector outputs require further review.";
    }

    styleVerdict("email-verdict-panel", "email-status-badge", style, verdict);
    setText("email-verdict-title", verdict);
    setText("email-verdict-description", description);
    const icon = $("email-verdict-icon");
    if (icon) icon.textContent = style === "phishing" ? "!" : style === "suspicious" ? "⚠" : "✓";
    setText("email-report-time", `Scanned on ${new Date().toLocaleString()}`);
    setText("email-rule-score", ruleRisk === null ? "Not available" : ruleRisk);
    setText("email-rule-verdict", rulePrediction);
    setText("email-ml-score", mlScore === null ? "Not available" : `${mlScore.toFixed(2)}%`);
    setProgress("email-ml-bar", mlScore);
    setText("email-agreement", typeof data.predictions_agree === "boolean" ? (data.predictions_agree ? "Agree" : "Differ") : "Not available");
    setText("email-agreement-note", typeof data.predictions_agree === "boolean" ? (data.predictions_agree ? "The configured agreement rule matched." : "The outputs differ or the agreement rule was not met.") : "Agreement was not returned.");
    setText("email-ml-verdict", mlPrediction);
    setText("email-safe-score", ml.safe_model_score !== undefined ? `ML safe score: ${ml.safe_model_score}%` : "");
    setText("email-method", `Method: ${ml.method || "Not specified"}`);
    addReasons("email-rule-reasons", rule.reasons);
    const actionPanel = $("email-action-panel");
    if (actionPanel) actionPanel.className = `action-panel ${style}`;
    setText("email-action-title", actionTitle);
    setText("email-action-copy", actionCopy);
    renderActionList("email-action-list", actions);
    $("email-report")?.classList.remove("hidden");
    $("email-report")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // Copy URL details safely; use clipboard when available and a fallback otherwise.
  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy]");
    if (!button) return;
    const target = $(button.dataset.copy);
    if (!target) return;
    const text = target.textContent || "";
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
      setTimeout(() => { button.textContent = "Copy"; }, 1200);
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(target);
      selection.removeAllRanges();
      selection.addRange(range);
    }
  });
})();
