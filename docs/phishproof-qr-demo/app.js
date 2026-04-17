const sampleUrls = {
  safe: "https://www.apple.com/iphone",
  shortener: "https://bit.ly/3secure-deal",
  lookalike: "https://paypaI-verification-login.com/secure",
  encoded: "https://verify-account-example.net/login?redirect=%68%74%74%70%73%3A%2F%2Fevil.example"
};

const dom = {
  urlInput: document.getElementById("urlInput"),
  analyzeButton: document.getElementById("analyzeButton"),
  clearButton: document.getElementById("clearButton"),
  sampleButtons: Array.from(document.querySelectorAll(".sample-button")),
  resultsSection: document.getElementById("resultsSection"),
  resultTitle: document.getElementById("resultTitle"),
  verdictBadge: document.getElementById("verdictBadge"),
  finalUrl: document.getElementById("finalUrl"),
  actionText: document.getElementById("actionText"),
  redirectChain: document.getElementById("redirectChain"),
  riskReasons: document.getElementById("riskReasons"),
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
  } else if (urlString.includes("verify-account-example.net")) {
    redirects.push("https://verify-account-example.net/continue");
    redirects.push("https://evil.example/credential-harvest");
  } else {
    redirects.push(urlString);
  }
  return redirects;
}

function analyzeUrl(rawValue) {
  const parsed = normalizeUrl(rawValue);
  const urlString = parsed.toString();
  const decodedPath = decodeIfNeeded(`${parsed.pathname}${parsed.search}`);
  const reasons = [];
  let score = 0;

  if (parsed.hostname.match(/^\d{1,3}(\.\d{1,3}){3}$/)) {
    score += 30;
    reasons.push("The QR code points to a raw IP address instead of a recognizable domain.");
  }
  const suspiciousTlds = [".zip", ".top", ".click", ".shop", ".help"];
  if (suspiciousTlds.some((tld) => parsed.hostname.endsWith(tld))) {
    score += 18;
    reasons.push("The destination uses a high-risk top-level domain that is often abused.");
  }
  if (parsed.hostname.includes("bit.ly") || parsed.hostname.includes("tinyurl") || parsed.hostname.includes("t.co")) {
    score += 22;
    reasons.push("The link uses a shortener, which hides the real destination.");
  }
  if (decodedPath !== `${parsed.pathname}${parsed.search}`) {
    score += 12;
    reasons.push("The URL contains encoded characters that can hide the true destination.");
  }
  if (/[I1l]{2,}/.test(parsed.hostname) || parsed.hostname.includes("paypaI")) {
    score += 34;
    reasons.push("The domain looks like a brand impersonation attempt or a lookalike typo.");
  }
  if (parsed.search.includes("redirect=")) {
    score += 14;
    reasons.push("The URL contains a redirect parameter, which can conceal the final destination.");
  }

  const redirects = buildRedirectChain(urlString);
  if (redirects.length > 2) {
    score += 12;
    reasons.push("The scan leads through multiple redirects before reaching the final page.");
  }

  if (parsed.hostname.endsWith("apple.com") || parsed.hostname.endsWith("microsoft.com")) {
    score -= 18;
    reasons.push("The destination matches a well-known domain with a lower apparent risk profile.");
  }

  if (reasons.length === 0) {
    reasons.push("No obvious phishing or malware signals were detected in this demo analysis.");
  }

  let verdict = "Safe";
  if (score >= 65) verdict = "Dangerous";
  else if (score >= 35) verdict = "Caution";

  const canAutoContinue = verdict === "Safe";
  const recommendedAction = canAutoContinue
    ? "No suspicious signals were found in the demo analysis. You can continue to the destination."
    : "Do not auto-open this QR destination. Review the reasons carefully and only continue if you trust the source.";

  return { verdict, score, urlString, redirects, reasons, recommendedAction, canAutoContinue };
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

  dom.redirectChain.innerHTML = "";
  result.redirects.forEach((hop) => {
    const item = document.createElement("li");
    item.textContent = hop;
    dom.redirectChain.appendChild(item);
  });

  dom.riskReasons.innerHTML = "";
  result.reasons.forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    dom.riskReasons.appendChild(item);
  });

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
  lastAnalysis = null;
});
dom.sampleButtons.forEach((button) => {
  button.addEventListener("click", () => {
    dom.urlInput.value = sampleUrls[button.dataset.sample];
    runAnalysis();
  });
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
  if (lastAnalysis.verdict !== "Safe") {
    window.alert("In the real app, higher-risk results would require explicit confirmation before opening.");
    return;
  }
  window.alert(`Demo action: continue to ${lastAnalysis.urlString}`);
});
