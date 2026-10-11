const form = document.getElementById("scan-form");
const input = document.getElementById("url-input");
const button = document.getElementById("scan-button");
const loading = document.getElementById("loading");
const errorBox = document.getElementById("error-box");
const report = document.getElementById("report");

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value === null || value === undefined || value === "" ? "Not available" : String(value);
}
function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}
function getVerdict(prediction) {
  if (prediction.includes("PHISHING")) return "phishing";
  if (prediction.includes("SUSPICIOUS")) return "suspicious";
  if (prediction.includes("LEGITIMATE")) return "legitimate";
  return "unknown";
}
function displayReport(data, submittedUrl) {
  const prediction = String(data.prediction || "UNKNOWN").toUpperCase();
  const verdict = getVerdict(prediction);
  const badge = document.getElementById("status-badge");
  const verdictPanel = document.getElementById("verdict-panel");
  const verdictIcon = document.getElementById("verdict-icon");
  const actionPanel = document.getElementById("action-panel");

  ["submitted-url", "hostname", "normalized-url"].forEach(id => setText(id, id === "submitted-url" ? submittedUrl : data[id.replace("-", "_")]));
  setText("hostname-metric", data.hostname);
  setText("risk-points", data.structural_risk_points);
  setText("report-time", `Scanned on ${new Date().toLocaleString()}`);

  const probability = Number(data.phishing_probability);
  const validProbability = Number.isFinite(probability) && probability >= 0 && probability <= 100;
  setText("phishing-probability", validProbability ? `${probability.toFixed(2)}%` : "Not available");
  const bar = document.getElementById("probability-bar");
  bar.style.width = validProbability ? `${probability}%` : "0%";
  bar.parentElement.setAttribute("aria-valuenow", validProbability ? String(probability) : "0");

  badge.textContent = prediction;
  badge.className = `status-badge ${verdict}`;
  verdictPanel.className = `verdict-panel ${verdict}`;
  actionPanel.className = `action-panel ${verdict}`;

  const verdicts = {
    phishing: {icon:"!", title:"High-risk classification", description:"The detector classified this URL as phishing. Treat it as unsafe until independently verified.", actionTitle:"Avoid interacting with this site", actionCopy:"Do not provide sensitive information on a site flagged as phishing.", actions:["Do not enter passwords or payment details.","Do not download files or approve unexpected prompts.","If you already shared credentials, change them on the official site and enable MFA."]},
    suspicious: {icon:"!", title:"Caution advised", description:"Warning thresholds were met. This is not proof of malicious activity, but the URL needs further verification.", actionTitle:"Verify before proceeding", actionCopy:"Pause and confirm that the domain is the one you intended to visit.", actions:["Avoid signing in or making payments for now.","Open the organisation's official site using a trusted bookmark or typed address.","Check the sender and message context if the link came from an email or text."]},
    legitimate: {icon:"✓", title:"No strong warning detected", description:"The configured detector did not raise a strong warning. This does not guarantee that the website is safe.", actionTitle:"Continue with normal caution", actionCopy:"A low-risk result is not a guarantee of trustworthiness.", actions:["Check the domain spelling carefully.","Be cautious with unexpected requests for money or credentials.","Use multi-factor authentication for important accounts."]},
    unknown: {icon:"?", title:"Result needs review", description:"The detector returned an unrecognized classification. Do not rely on this result.", actionTitle:"Review manually", actionCopy:"The result could not be mapped to a known status.", actions:["Do not enter sensitive information until verified.","Check the domain using a trusted source."]}
  };
  const config = verdicts[verdict];
  setText("verdict-title", config.title);
  setText("prediction-description", config.description);
  verdictIcon.textContent = config.icon;
  setText("action-title", config.actionTitle);
  setText("action-copy", config.actionCopy);

  const actionList = document.getElementById("action-list");
  actionList.replaceChildren();
  config.actions.forEach(action => { const li = document.createElement("li"); li.textContent = action; actionList.appendChild(li); });

  const risk = Number(data.structural_risk_points);
  setText("risk-description", Number.isFinite(risk) ? (risk >= 30 ? "Elevated rule-based risk indicators." : risk >= 15 ? "Some structural warning indicators." : "Few configured structural warning points.") : "Based on configured URL rules.");

  const reasonsList = document.getElementById("reasons-list");
  reasonsList.replaceChildren();
  const reasons = Array.isArray(data.reasons) ? data.reasons : [];
  if (!reasons.length) {
    const li = document.createElement("li");
    li.className = "finding-empty";
    li.textContent = "No specific explanation was returned. Treat this as a limited model output, not a guarantee.";
    reasonsList.appendChild(li);
  } else {
    reasons.forEach(reason => {
      const li = document.createElement("li"); li.className = "finding-item";
      const icon = document.createElement("span"); icon.className = "finding-mark"; icon.textContent = verdict === "legitimate" ? "i" : "!"; icon.setAttribute("aria-hidden", "true");
      const text = document.createElement("span"); text.textContent = String(reason);
      li.append(icon, text); reasonsList.appendChild(li);
    });
  }
  report.classList.remove("hidden");
  report.scrollIntoView({behavior:"smooth", block:"start"});
}
form.addEventListener("submit", async event => {
  event.preventDefault();
  const url = input.value.trim();
  if (!url) { showError("Please enter a website URL."); return; }
  errorBox.classList.add("hidden"); report.classList.add("hidden"); loading.classList.remove("hidden");
  button.disabled = true; button.innerHTML = "<span>Scanning…</span><span aria-hidden='true'>↻</span>";
  try {
    const response = await fetch("/check-url", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({url})});
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The URL could not be analyzed.");
    displayReport(data, url);
  } catch (error) {
    showError(error.message || "Could not connect to the backend. Check that the API is running.");
  } finally {
    loading.classList.add("hidden"); button.disabled = false; button.innerHTML = "<span>Scan website</span><span aria-hidden='true'>→</span>";
  }
});
document.getElementById("print-button").addEventListener("click", () => window.print());
document.querySelectorAll(".copy-button").forEach(button => {
  button.addEventListener("click", async () => {
    const target = document.getElementById(button.dataset.copy);
    const original = button.textContent;
    try { await navigator.clipboard.writeText(target.textContent); button.textContent = "Copied"; }
    catch { button.textContent = "Select text"; }
    setTimeout(() => { button.textContent = original; }, 1200);
  });
});
