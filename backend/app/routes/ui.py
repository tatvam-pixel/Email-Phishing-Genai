"""Single-page web interface for PhishGuard AI prototype."""

from flask import Blueprint, Response

ui_bp = Blueprint("ui", __name__)

_HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PhishGuard AI — Demo Prototype</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #e6edf3;
      --text-muted: #8b949e;
      --primary: #238636;
      --primary-hover: #2ea043;
      --btn-secondary: #21262d;
      --btn-secondary-hover: #30363d;
      --danger: #da3633;
      --warning: #d29922;
      --info: #58a6ff;
      --badge-safe: #238636;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      padding: 24px 16px;
    }
    .container {
      max-width: 820px;
      margin: 0 auto;
    }
    header {
      margin-bottom: 24px;
      text-align: center;
    }
    header h1 {
      font-size: 28px;
      margin-bottom: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
    }
    header p {
      color: var(--text-muted);
      font-size: 14px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .field-group {
      margin-bottom: 16px;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 6px;
      color: var(--text);
    }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 10px 12px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 14px;
    }
    input:focus {
      outline: none;
      border-color: var(--info);
    }
    .sample-buttons {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 16px;
    }
    .btn-sample {
      background: var(--btn-secondary);
      color: var(--text);
      border: 1px solid var(--border);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      cursor: pointer;
      transition: background 0.15s ease;
    }
    .btn-sample:hover {
      background: var(--btn-secondary-hover);
    }
    .btn-primary {
      background: var(--primary);
      color: #fff;
      border: none;
      padding: 10px 20px;
      border-radius: 6px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      width: 100%;
      transition: background 0.15s ease;
    }
    .btn-primary:hover {
      background: var(--primary-hover);
    }
    .btn-primary:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }
    .spinner-wrap {
      display: none;
      text-align: center;
      padding: 20px 0;
    }
    .spinner {
      border: 3px solid rgba(255, 255, 255, 0.1);
      border-top: 3px solid var(--info);
      border-radius: 50%;
      width: 28px;
      height: 28px;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 8px;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .error-box {
      display: none;
      background: rgba(218, 54, 51, 0.15);
      border: 1px solid var(--danger);
      border-radius: 6px;
      padding: 12px;
      margin-bottom: 16px;
      color: #f85149;
      font-size: 14px;
    }
    .result-section {
      display: none;
    }
    .result-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border);
      flex-wrap: wrap;
      gap: 12px;
    }
    .badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .badge-high_risk { background: rgba(218, 54, 51, 0.2); color: #f85149; border: 1px solid var(--danger); }
    .badge-suspicious { background: rgba(210, 153, 34, 0.2); color: #e3b341; border: 1px solid var(--warning); }
    .badge-low_risk { background: rgba(35, 134, 54, 0.2); color: #3fb950; border: 1px solid var(--primary); }
    .meta-row {
      display: flex;
      gap: 20px;
      font-size: 13px;
      color: var(--text-muted);
    }
    .meta-row strong {
      color: var(--text);
    }
    .section-title {
      font-size: 15px;
      font-weight: 600;
      margin: 16px 0 8px;
      color: var(--text);
    }
    .evidence-item {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      margin-bottom: 8px;
      display: flex;
      flex-direction: column;
      gap: 4px;
      font-size: 13px;
    }
    .evidence-top {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .severity-tag {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      padding: 2px 6px;
      border-radius: 4px;
    }
    .sev-high { background: #da3633; color: #fff; }
    .sev-medium { background: #d29922; color: #000; }
    .sev-low { background: #58a6ff; color: #000; }
    .sev-info { background: #8b949e; color: #000; }
    .explanation-box {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
      font-size: 13px;
    }
    .explanation-box p {
      margin-bottom: 10px;
    }
    ul.item-list {
      list-style-type: disc;
      padding-left: 20px;
      font-size: 13px;
      color: var(--text);
    }
    ul.item-list li {
      margin-bottom: 4px;
    }
    footer.status-panel {
      margin-top: 24px;
      padding: 16px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      font-size: 12px;
      color: var(--text-muted);
    }
    .status-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-top: 8px;
    }
    .status-col h4 {
      font-size: 13px;
      color: var(--text);
      margin-bottom: 4px;
    }
    .status-col ul {
      list-style-type: square;
      padding-left: 16px;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🛡️ PhishGuard AI</h1>
      <p>Demonstration Prototype — Structural URL Analysis &amp; Gemini Threat Explanation</p>
    </header>

    <div class="card">
      <div class="field-group">
        <label for="apiKey">API Key (X-API-Key)</label>
        <input type="password" id="apiKey" placeholder="Enter API key" autocomplete="off" />
      </div>

      <div class="field-group">
        <label for="urlInput">Target URL to Analyse</label>
        <input type="text" id="urlInput" placeholder="https://example.com/login" />
      </div>

      <label>Sample URLs</label>
      <div class="sample-buttons">
        <button type="button" class="btn-sample" id="sampleGoogle">Google Sign-in (Legitimate)</button>
        <button type="button" class="btn-sample" id="samplePaypal">PayPal Lookalike on .xyz (Suspicious)</button>
        <button type="button" class="btn-sample" id="sampleIp">IP Login URL (High Risk)</button>
      </div>

      <button type="button" id="analyseBtn" class="btn-primary">Analyse URL</button>

      <div id="spinnerWrap" class="spinner-wrap">
        <div class="spinner"></div>
        <p style="font-size:13px; color:var(--text-muted)">Scanning URL and querying Gemini explanation...</p>
      </div>
    </div>

    <div id="errorBox" class="error-box"></div>

    <div id="resultSection" class="card result-section">
      <div class="result-header">
        <div>
          <span id="classificationBadge" class="badge"></span>
        </div>
        <div class="meta-row">
          <div>Risk Score: <strong id="scoreVal"></strong>/100</div>
          <div>Confidence: <strong id="confidenceVal"></strong></div>
          <div>Scan ID: <strong id="scanIdVal"></strong></div>
        </div>
      </div>

      <div class="section-title">Evidence &amp; Threat Indicators</div>
      <div id="evidenceList"></div>

      <div class="section-title">AI Threat Explanation</div>
      <div class="explanation-box">
        <p id="aiSummary" style="font-weight:600;"></p>
        <div id="aiReasonsWrap">
          <div style="font-weight:600; margin-bottom:6px; color:var(--text-muted);">Cited Reasons:</div>
          <ul id="aiReasonsList" class="item-list"></ul>
        </div>
        <div id="aiRecsWrap" style="margin-top:10px;">
          <div style="font-weight:600; margin-bottom:6px; color:var(--text-muted);">Recommendations:</div>
          <ul id="aiRecsList" class="item-list"></ul>
        </div>
      </div>

      <div class="section-title">Assessment Limitations</div>
      <ul id="limitationsList" class="item-list"></ul>
    </div>

    <footer class="status-panel">
      <h3 style="font-size:14px; color:var(--text); margin-bottom:4px;">Prototype status</h3>
      <div class="status-grid">
        <div class="status-col">
          <h4>Done</h4>
          <ul>
            <li>Scan API (/api/v1/scan/url)</li>
            <li>API key authentication (SHA-256 constant-time)</li>
            <li>Gemini explanation (grounded in backend evidence)</li>
            <li>OpenAPI interactive docs (/docs)</li>
          </ul>
        </div>
        <div class="status-col">
          <h4>Next</h4>
          <ul>
            <li>Database-backed keys and audit logs</li>
            <li>Webhooks (HMAC-signed scan.completed events)</li>
            <li>Message scanner (text and link extraction)</li>
          </ul>
        </div>
      </div>
    </footer>
  </div>

  <script>
    (function() {
      var apiKeyInput = document.getElementById("apiKey");
      var urlInput = document.getElementById("urlInput");
      var analyseBtn = document.getElementById("analyseBtn");
      var spinnerWrap = document.getElementById("spinnerWrap");
      var errorBox = document.getElementById("errorBox");
      var resultSection = document.getElementById("resultSection");

      var classificationBadge = document.getElementById("classificationBadge");
      var scoreVal = document.getElementById("scoreVal");
      var confidenceVal = document.getElementById("confidenceVal");
      var scanIdVal = document.getElementById("scanIdVal");
      var evidenceList = document.getElementById("evidenceList");
      var aiSummary = document.getElementById("aiSummary");
      var aiReasonsList = document.getElementById("aiReasonsList");
      var aiRecsList = document.getElementById("aiRecsList");
      var limitationsList = document.getElementById("limitationsList");

      // Sample URLs
      document.getElementById("sampleGoogle").addEventListener("click", function() {
        urlInput.value = "https://accounts.google.com/signin";
      });
      document.getElementById("samplePaypal").addEventListener("click", function() {
        urlInput.value = "http://paypal.secure-login.verify-account.xyz/update";
      });
      document.getElementById("sampleIp").addEventListener("click", function() {
        urlInput.value = "http://192.168.1.1/login";
      });

      function clearNode(node) {
        while (node.firstChild) {
          node.removeChild(node.firstChild);
        }
      }

      function showError(msg) {
        errorBox.textContent = msg;
        errorBox.style.display = "block";
      }

      function hideError() {
        errorBox.textContent = "";
        errorBox.style.display = "none";
      }

      analyseBtn.addEventListener("click", function() {
        hideError();
        resultSection.style.display = "none";

        var apiKey = apiKeyInput.value.trim();
        var targetUrl = urlInput.value.trim();

        if (!targetUrl) {
          showError("Please enter a URL to analyse.");
          return;
        }

        analyseBtn.disabled = true;
        spinnerWrap.style.display = "block";

        fetch("/api/v1/scan/url", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-API-Key": apiKey
          },
          body: JSON.stringify({
            url: targetUrl,
            include_ai_analysis: true
          })
        })
        .then(function(res) {
          return res.json().then(function(data) {
            return { status: res.status, data: data };
          });
        })
        .then(function(payload) {
          analyseBtn.disabled = false;
          spinnerWrap.style.display = "none";

          if (payload.status !== 200 || !payload.data.success) {
            var errMsg = (payload.data && payload.data.error && payload.data.error.message)
              ? payload.data.error.message
              : "Scan failed (HTTP " + payload.status + ")";
            showError(errMsg);
            return;
          }

          var result = payload.data.result;
          var scanId = payload.data.scan_id;

          // Render metadata safely with textContent
          scanIdVal.textContent = scanId || "";
          scoreVal.textContent = String(result.risk_score);
          confidenceVal.textContent = String(result.confidence);

          // Classification wording: never write the word safe; low_risk shows "No strong indicators found"
          var cls = result.classification || "low_risk";
          classificationBadge.className = "badge badge-" + cls;
          if (cls === "low_risk") {
            classificationBadge.textContent = "No strong indicators found";
          } else if (cls === "suspicious") {
            classificationBadge.textContent = "Suspicious";
          } else if (cls === "high_risk") {
            classificationBadge.textContent = "High Risk";
          } else {
            classificationBadge.textContent = cls;
          }

          // Evidence list
          clearNode(evidenceList);
          if (result.evidence && result.evidence.length > 0) {
            result.evidence.forEach(function(ev) {
              var item = document.createElement("div");
              item.className = "evidence-item";

              var topRow = document.createElement("div");
              topRow.className = "evidence-top";

              var tag = document.createElement("span");
              tag.className = "severity-tag sev-" + (ev.severity || "info");
              tag.textContent = ev.severity || "info";

              var refSpan = document.createElement("strong");
              refSpan.textContent = "[" + (ev.ref || "") + "] " + (ev.indicator || "");

              topRow.appendChild(tag);
              topRow.appendChild(refSpan);

              var desc = document.createElement("div");
              desc.textContent = ev.description || "";

              item.appendChild(topRow);
              item.appendChild(desc);
              evidenceList.appendChild(item);
            });
          } else {
            var noEv = document.createElement("p");
            noEv.style.color = "var(--text-muted)";
            noEv.style.fontSize = "13px";
            noEv.textContent = "No threat indicators matched.";
            evidenceList.appendChild(noEv);
          }

          // AI Explanation
          var ai = result.ai_explanation;
          clearNode(aiReasonsList);
          clearNode(aiRecsList);

          if (ai) {
            aiSummary.textContent = ai.summary || "";

            if (ai.reasons && ai.reasons.length > 0) {
              ai.reasons.forEach(function(r) {
                var li = document.createElement("li");
                var refs = (r.evidence_refs && r.evidence_refs.length > 0) ? " (" + r.evidence_refs.join(", ") + ")" : "";
                li.textContent = (r.text || "") + refs;
                aiReasonsList.appendChild(li);
              });
            }

            if (ai.recommendations && ai.recommendations.length > 0) {
              ai.recommendations.forEach(function(rec) {
                var li = document.createElement("li");
                li.textContent = rec;
                aiRecsList.appendChild(li);
              });
            }
          } else {
            aiSummary.textContent = "AI analysis was not included or requested.";
          }

          // Limitations
          clearNode(limitationsList);
          if (result.limitations && result.limitations.length > 0) {
            result.limitations.forEach(function(lim) {
              var li = document.createElement("li");
              li.textContent = lim;
              limitationsList.appendChild(li);
            });
          }

          resultSection.style.display = "block";
        })
        .catch(function(err) {
          analyseBtn.disabled = false;
          spinnerWrap.style.display = "none";
          showError("Network or unexpected error: " + err.message);
        });
      });
    })();
  </script>
</body>
</html>
"""


@ui_bp.get("/")
def index():
    """Serve the single-page prototype web interface."""
    return Response(_HTML_PAGE, mimetype="text/html")
