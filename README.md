# Browser Security Analysis Toolkit v3.0

A modular, **non-destructive** runtime reconnaissance framework for educational and authorized security research directly from your browser's DevTools Console.

> ⚠️ **Authorized use only.** Run this toolkit only on websites you own or have explicit permission to test.

---

## Features

| Module | What it does |
|---|---|
| 🌐 **Network Monitor** | Hooks `fetch()` and `XMLHttpRequest` to log all requests with method, status, timing, and cross-origin flags |
| 🔑 **Token Analyzer** | Inspects hidden `<input>` fields, calculates Shannon entropy, and watches for live token rotation |
| 🗺 **Event Mapper** | Enumerates all forms, methods, CSRF tokens, inline event handlers, and sensitive field names |
| 🗄 **Storage Analyzer** | Reads `localStorage`, `sessionStorage`, and cookies; flags sensitive keys and high-entropy values |
| 📜 **Script Analyzer** | Catalogs external scripts by domain (CDN / analytics / third-party), checks for missing SRI attributes, and detects inline `eval()` usage |
| 🚨 **Security Signals** | Detects iframe embedding, mixed content, open-redirect parameters, missing CSRF tokens, and sensitive data in the URL |
| ⚡ **Performance Monitor** | Reports DOM node count, page load time, script/stylesheet count, and long tasks |
| 🧩 **DOM Analyzer** | Hooks dangerous DOM sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`) and watches for dynamic script/iframe injection |

All modules are **observe-only** — no data is modified or exfiltrated.

---

## Quick Start

1. Open the target web page in your browser.
2. Open **DevTools** (`F12` on Windows/Linux, `⌘ Opt I` on macOS).
3. Go to the **Console** tab.
4. Copy the entire contents of [`security_toolkit .js`](security_toolkit%20.js) and paste it into the console.
5. Press **Enter**.

The toolkit initializes immediately and prints a color-coded analysis report.

---

## Reading the Output

### Color coding

| Color | Meaning |
|---|---|
| 🟢 Green | Safe / expected |
| 🟡 Yellow | Warning — worth investigating |
| 🔴 Red | High-risk finding |
| 🔵 Blue | Informational |

### Risk Score

At the end of each run an **Executive Summary** is printed with a risk score from `0` to `100`:

| Score | Classification |
|---|---|
| 0 – 24 | ✅ Minimal Risk |
| 25 – 59 | ⚠️ Moderate Surface |
| 60 – 100 | 🚨 High Attack Surface |

Scores are computed using a weighted sum of security signals:
- **High** signals → ×10 points each
- **Medium** signals → ×4 points each
- **Low** signals → ×1 point each

---

## Exporting a Report

After the scan completes, call the following from the console to export a full JSON report:

```js
window.Toolkit.exportReport()
```

To save it to a file:

```js
const data = JSON.stringify(window.Toolkit.exportReport(), null, 2);
const blob = new Blob([data], { type: 'application/json' });
const a = document.createElement('a');
a.href = URL.createObjectURL(blob);
a.download = 'security-report.json';
a.click();
```

The exported report includes:

- `version` / `timestamp` / `target`
- `riskScore` and `riskLabel`
- `signals` — high / medium / low categorised findings
- `endpoints` — detected API endpoints
- `thirdPartyDomains`
- `requests` — all captured network requests (method, URL, status, timing, size)
- `tokens` — hidden input fields with entropy metadata *(values are redacted)*
- `cookies` — cookie names with entropy *(values are not included)*
- `domStats` — node count, depth, iframe count, tag variety, DOM entropy
- `sinkInvocations` — DOM sink calls detected at runtime
- `formAnalysis` — form structure summary
- `scriptTagsAdded` — dynamically injected scripts

---

## Accessing Live State

The full internal state is accessible while the page is open:

```js
window.Toolkit.state           // complete state object
window.Toolkit.state.requests  // all captured network requests
window.Toolkit.state.cookies   // cookie details
window.Toolkit.state.riskScore // current risk score
```

---

## Requirements

- Any modern browser with a DevTools Console (Chrome, Edge, Firefox, Safari)
- No installation, no build step, no dependencies

---

## Disclaimer

This tool is intended **solely for educational purposes and authorized security research**. Do not use it on systems you do not own or do not have explicit written permission to test. The authors accept no liability for misuse.
