const sampleUrls = {
  safe: "https://www.apple.com/iphone",
  shortener: "https://bit.ly/3secure-deal",
  lookalike: "https://paypaI-verification-login.com/secure",
  encoded: "https://verify-account-example.net/login?redirect=%68%74%74%70%73%3A%2F%2Fevil.example",
  malware: "http://download-secure-update.top/update-app/installer.apk?payload=1",
  fileshare: "https://me-qr.com/r/fake-school-drive",
  tampered: "https://pay-parking-now-secure.top/pay",
  vcard: "https://contact-sync-card.info/open?vcard=1&redirect=https://download-secure-update.top/app.apk"
};

const dom = {
  urlInput: document.getElementById("urlInput"),
  analyzeButton: document.getElementById("analyzeButton"),
  clearButton: document.getElementById("clearButton"),
  sampleButtons: Array.from(document.querySelectorAll(".sample-button")),
  simulateScanButton: document.getElementById("simulateScanButton"),
  qrImageInput: document.getElementById("qrImageInput"),
  uploadPreview: document.getElementById("uploadPreview"),
  previewImage: document.getElementById("previewImage"),
  scanStatus: document.getElementById("scanStatus"),
  qrFrame: document.getElementById("qrFrame"),
  resultsSection: document.getElementById("resultsSection"),
  resultTitle: document.getElementById("resultTitle"),
  verdictBadge: document.getElementById("verdictBadge"),
  finalUrl: document.getElementById("finalUrl"),
  actionText: document.getElementById("actionText"),
  threatTags: document.getElementById("threatTags"),
  redirectChain: document.getElementById("redirectChain"),
  riskReasons: document.getElementById("riskReasons"),
  scoreValue: document.getElementById("scoreValue"),
  signalList: document.getElementById("signalList"),
  actionGate: document.getElementById("actionGate"),
  threatClass: document.getElementById("threatClass"),
  recommendedAction: document.getElementById("recommendedAction"),
  continueButton: document.getElementById("continueButton"),
  copyButton: document.getElementById("copyButton"),
  autoContinueToggle: document.getElementById("autoContinueToggle")
};

let lastAnalysis = null;

function normalizeUrl(raw) {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error("Paste a URL to analyze.");
  if (!/^https?:\/\//i.test(trimmed)) return new URL(`https://${trimmed}`);
  return new URL(trimmed);
}

function decodeIfNeeded(value) {
  try { return decodeURIComponent(value); } catch { return value; }
}

function buildRedirectChain(urlString) {
  const redirects = [urlString];
  if (urlString.includes("bit.ly")) {
    redirects.push("https://offer-checkpoint.net/landing");
    redirects.push("https://secure-apple-support.help/check");
  } else if (urlString.includes("me-qr.com") || urlString.includes("qrco.de") || urlString.includes("qrs.ly")) {
    redirects.push("https://shared-docs-captcha.top/verify-human");
    redirects.push("https://cdnimg.jeayacrai.in.net/outlook-session-check");
  } else if (urlString.includes("verify-account-example.net")) {
    redirects.push("https://verify-account-example.net/continue");
    redirects.push("https://evil.example/credential-harvest");
  } else if (urlString.includes("update-app")) {
    redirects.push("http://download-secure-update.top/payload/start");
    redirects.push("http://cdn-secure-package.top/app-release.apk");
  } else if (urlString.includes("pay-parking-now-secure.top")) {
    redirects.push("https://pay-parking-now-secure.top/session");
    redirects.push("https://pay-parking-now-secure.top/card-entry");
  } else {
    redirects.push(urlString);
  }
  return redirects;
}

function analyzeUrl(rawValue) {
  const parsed = normalizeUrl(rawValue);
  const urlString = parsed.toString();
  const lowerUrl = urlString.toLowerCase();
  const decodedPath = decodeIfNeeded(`${parsed.pathname}${parsed.search}`);
  const reasons = [];
  const tags = [];
  let score = 0;
  let threatClass = "Low-risk web destination";

  if (parsed.hostname.match(/^\d{1,3}(\.\d{1,3}){3}$/)) {
    score += 30;
    reasons.push("The QR code points to a raw IP address instead of a recognizable domain.");
    tags.push("IP host");
  }

  const suspiciousTlds = [".zip", ".top", ".click", ".shop", ".help"];
  if (suspiciousTlds.some((tld) => parsed.hostname.endsWith(tld))) {
    score += 18;
    reasons.push("The destination uses a high-risk top-level domain that is often abused.");
    tags.push("Suspicious TLD");
  }

  const knownShorteners = ["bit.ly", "tinyurl", "t.co", "qrco.de", "me-qr.com", "qrs.ly"];
  if (knownShorteners.some((domain) => parsed.hostname.includes(domain))) {
    score += 22;
    reasons.push("The link uses a shortener, which hides the real destination.");
    tags.push("Shortener");
  }

  if (decodedPath !== `${parsed.pathname}${parsed.search}`) {
    score += 12;
    reasons.push("The URL contains encoded characters that can hide the true destination.");
    tags.push("Encoded URL");
  }

  if (/[I1l]{2,}/.test(parsed.hostname) || parsed.hostname.includes("paypaI")) {
    score += 34;
    reasons.push("The domain looks like a brand impersonation attempt or a lookalike typo.");
    tags.push("Lookalike domain");
  }

  if (parsed.search.includes("redirect=")) {
    score += 14;
    reasons.push("The URL contains a redirect parameter, which can conceal the final destination.");
    tags.push("Redirect parameter");
  }

  if (parsed.username || parsed.password) {
    score += 28;
    reasons.push("The URL contains embedded credentials, which is a classic phishing trick.");
    tags.push("Embedded credentials");
  }

  if (parsed.protocol !== "https:") {
    score += 20;
    reasons.push("The destination is not using HTTPS, so the connection is less trustworthy.");
    tags.push("No HTTPS");
  }

  if ((parsed.hostname.match(/-/g) || []).length >= 3) {
    score += 10;
    reasons.push("The hostname uses many hyphens, which is common in throwaway phishing domains.");
    tags.push("Hyphen-heavy host");
  }

  const fileShareIndicators = ["drive", "shared", "cdn", "files", "docs", "download"];
  if (fileShareIndicators.filter((keyword) => lowerUrl.includes(keyword)).length >= 2) {
    score += 14;
    reasons.push("The destination looks like a file-sharing or CDN-style flow, which is commonly abused for malware and phishing chains.");
    tags.push("File-sharing chain");
  }

  const captchaIndicators = ["captcha", "verify-human", "robot", "recaptcha"];
  if (captchaIndicators.some((keyword) => lowerUrl.includes(keyword))) {
    score += 14;
    reasons.push("The redirect chain includes CAPTCHA-style gating, which attackers often use to make malicious flows look legitimate.");
    tags.push("CAPTCHA gate");
  }

  const phishingKeywords = ["verify", "secure", "login", "account", "update", "wallet", "password"];
  const keywordHits = phishingKeywords.filter((keyword) => lowerUrl.includes(keyword));
  if (keywordHits.length >= 3) {
    score += 18;
    reasons.push("The URL combines several urgency or account-related keywords often seen in phishing attacks.");
    tags.push("Phishing keywords");
  }

  const malwareKeywords = ["apk", "download", "installer", "update-app", "payload"];
  const malwareHits = malwareKeywords.filter((keyword) => lowerUrl.includes(keyword));
  if (malwareHits.length >= 2) {
    score += 20;
    reasons.push("The URL looks like it may be pushing a download or payload delivery flow.");
    tags.push("Malware delivery");
  }

  const contextKeywords = ["parking", "meter", "menu", "restaurant", "atm", "crypto"];
  if (contextKeywords.some((keyword) => lowerUrl.includes(keyword))) {
    score += 10;
    reasons.push("This looks like a high-risk public QR context such as parking, menus, or payment flows where physical tampering is common.");
    tags.push("Quishing context");
  }

  const calendarContactKeywords = ["vcard", "contact", "calendar", "invite", "ics"];
  if (calendarContactKeywords.some((keyword) => lowerUrl.includes(keyword))) {
    score += 14;
    reasons.push("The payload appears to involve contact or calendar content, which can hide malicious URLs or unsafe downloads.");
    tags.push("Contact/calendar payload");
  }

  const redirects = buildRedirectChain(urlString);
  if (redirects.length > 2) {
    score += 12;
    reasons.push("The scan leads through multiple redirects before reaching the final page.");
    tags.push("Multi-hop redirect");
  }

  if (parsed.hostname.endsWith("apple.com") || parsed.hostname.endsWith("microsoft.com")) {
    score -= 18;
    reasons.push("The destination matches a well-known domain with a lower apparent risk profile.");
    tags.push("Trusted brand");
  }

  if (reasons.length === 0) {
    reasons.push("No obvious phishing or malware signals were detected in this demo analysis.");
    tags.push("No major signals");
  }

  let verdict = "Safe";
  if (score >= 65) verdict = "Dangerous";
  else if (score >= 35) verdict = "Caution";

  if (tags.includes("Malware delivery") || tags.includes("File-sharing chain")) {
    threatClass = "Possible malware delivery";
  } else if (tags.includes("Lookalike domain") || tags.includes("Embedded credentials") || tags.includes("Phishing keywords")) {
    threatClass = "Likely phishing attempt";
  } else if (verdict === "Safe") {
    threatClass = "Low-risk web destination";
  } else {
    threatClass = "Suspicious web destination";
  }

  return {
    verdict,
    score,
    urlString,
    redirects,
    reasons,
    tags,
    threatClass,
    canAutoContinue: verdict === "Safe",
    recommendedAction: verdict === "Safe"
      ? "No suspicious signals were found in the demo analysis. You can continue to the destination."
      : "Do not auto-open this QR destination. Review the reasons carefully and only continue if you trust the source."
  };
}

function renderList(listElement, values) {
  listElement.innerHTML = "";
  values.forEach((value) => {
    const item = document.createElement("li");
    item.textContent = value;
    listElement.appendChild(item);
  });
}

function renderTags(tags) {
  dom.threatTags.innerHTML = "";
  tags.forEach((tag) => {
    const chip = document.createElement("span");
    chip.className = "threat-tag";
    chip.textContent = tag;
    dom.threatTags.appendChild(chip);
  });
}

function renderAnalysis(result) {
  lastAnalysis = result;
  dom.resultsSection.classList.remove("hidden");
  dom.resultTitle.textContent = result.verdict === "Safe" ? "Low-risk result" : `${result.verdict} result`;
  dom.verdictBadge.textContent = result.verdict;
  dom.verdictBadge.className = "verdict-badge";
  dom.verdictBadge.classList.add(
    result.verdict === "Safe" ? "verdict-safe" : result.verdict === "Caution" ? "verdict-caution" : "verdict-dangerous"
  );

  dom.finalUrl.textContent = result.urlString;
  dom.actionText.textContent = result.canAutoContinue
    ? "Decoded action: open website. This can be continued from the same screen."
    : "Decoded action: website link. Manual review is recommended before continuing.";

  renderTags(result.tags);
  renderList(dom.redirectChain, result.redirects);
  renderList(dom.riskReasons, result.reasons);
  renderList(dom.signalList, result.reasons.slice(0, 3));
  dom.scoreValue.textContent = String(Math.max(result.score, 0));
  dom.actionGate.textContent = result.canAutoContinue
    ? "Eligible for low-risk continuation. If safe mode is enabled, the app can move forward without rescanning."
    : "Manual approval required. The app should pause and explain the risk before any action executes.";
  dom.threatClass.textContent = result.threatClass;

  dom.recommendedAction.textContent = result.recommendedAction;
  dom.continueButton.textContent = result.canAutoContinue && dom.autoContinueToggle.checked
    ? "Auto-continue triggered"
    : "Continue safely";

  if (result.canAutoContinue && dom.autoContinueToggle.checked) {
    dom.recommendedAction.textContent = "Safe mode is enabled, so the app would continue automatically without a second scan.";
  }
}

function runAnalysis() {
  try {
    dom.scanStatus.textContent = "QR decoded. Running destination analysis and risk checks.";
    const result = analyzeUrl(dom.urlInput.value);
    renderAnalysis(result);
    dom.resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    window.alert(error.message);
  }
}

dom.analyzeButton.addEventListener("click", runAnalysis);

dom.clearButton.addEventListener("click", () => {
  dom.urlInput.value = "";
  dom.resultsSection.classList.add("hidden");
  dom.uploadPreview.classList.add("hidden");
  dom.previewImage.removeAttribute("src");
  dom.scanStatus.textContent = "Waiting for a scan or pasted QR destination.";
  lastAnalysis = null;
});

dom.sampleButtons.forEach((button) => {
  button.addEventListener("click", () => {
    dom.urlInput.value = sampleUrls[button.dataset.sample];
    runAnalysis();
  });
});

dom.simulateScanButton.addEventListener("click", () => {
  dom.scanStatus.textContent = "iPhone camera locked onto QR code. Decoding payload...";
  dom.qrFrame.classList.add("scanning");
  dom.urlInput.value = sampleUrls.safe;
  window.setTimeout(() => {
    dom.scanStatus.textContent = "QR payload found. Preparing safety analysis.";
    dom.qrFrame.classList.remove("scanning");
    runAnalysis();
  }, 1400);
});

dom.qrImageInput.addEventListener("change", (event) => {
  const [file] = event.target.files || [];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    dom.previewImage.src = reader.result;
    dom.uploadPreview.classList.remove("hidden");
    dom.scanStatus.textContent = "Camera or photo input received. On iPhone, the full product would decode the QR directly from this capture flow.";
  };
  reader.readAsDataURL(file);
});

dom.copyButton.addEventListener("click", async () => {
  if (!lastAnalysis) return;
  try {
    await navigator.clipboard.writeText(lastAnalysis.urlString);
    dom.copyButton.textContent = "Copied";
    setTimeout(() => { dom.copyButton.textContent = "Copy URL"; }, 1200);
  } catch {
    window.alert("Clipboard copy failed in this browser.");
  }
});

dom.continueButton.addEventListener("click", () => {
  if (!lastAnalysis) return;
  if (!lastAnalysis.canAutoContinue) {
    window.alert("In the real app, higher-risk results would require explicit confirmation before opening.");
    return;
  }
  window.alert(`Demo action: continue to ${lastAnalysis.urlString}`);
});
