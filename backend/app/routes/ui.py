"""Single-page web interface for PhishGuard AI prototype with Google OAuth authentication."""

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
    .auth-banner {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 20px;
      font-size: 13px;
    }
    .btn-google {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      background: #ffffff;
      color: #1f1f1f;
      font-weight: 600;
      font-size: 13px;
      padding: 8px 16px;
      border-radius: 6px;
      text-decoration: none;
      border: 1px solid #747775;
      transition: background 0.15s ease;
    }
    .btn-google:hover {
      background: #f2f2f2;
    }
    .btn-logout {
      background: transparent;
      color: #f85149;
      font-size: 13px;
      padding: 6px 12px;
      border: 1px solid rgba(218, 54, 51, 0.4);
      border-radius: 6px;
      cursor: pointer;
      transition: background 0.15s ease;
    }
    .btn-logout:hover {
      background: rgba(218, 54, 51, 0.15);
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
    input[type="text"] {
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

    <!-- Authentication status banner -->
    <div id="unauthBanner" class="auth-banner" style="display:none;">
      <span>Sign in with Google to perform URL security scans:</span>
      <a href="/auth/login" class="btn-google">
        <svg width="16" height="16" viewBox="0 0 24 24">
          <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
          <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
          <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
          <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
        </svg>
        Continue with Google
      </a>
    </div>

    <div id="authBanner" class="auth-banner" style="display:none;">
      <span>Signed in as <strong id="userEmailDisplay"></strong></span>
      <button type="button" id="logoutBtn" class="btn-logout">Sign out</button>
    </div>

    <div class="card">
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
            <li>Google OAuth 2.0 &amp; Session Auth (CSRF-protected)</li>
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
      var urlInput = document.getElementById("urlInput");
      var analyseBtn = document.getElementById("analyseBtn");
      var logoutBtn = document.getElementById("logoutBtn");
      var spinnerWrap = document.getElementById("spinnerWrap");
      var errorBox = document.getElementById("errorBox");
      var resultSection = document.getElementById("resultSection");

      var unauthBanner = document.getElementById("unauthBanner");
      var authBanner = document.getElementById("authBanner");
      var userEmailDisplay = document.getElementById("userEmailDisplay");

      var classificationBadge = document.getElementById("classificationBadge");
      var scoreVal = document.getElementById("scoreVal");
      var confidenceVal = document.getElementById("confidenceVal");
      var scanIdVal = document.getElementById("scanIdVal");
      var evidenceList = document.getElementById("evidenceList");
      var aiSummary = document.getElementById("aiSummary");
      var aiReasonsList = document.getElementById("aiReasonsList");
      var aiRecsList = document.getElementById("aiRecsList");
      var limitationsList = document.getElementById("limitationsList");

      var currentCsrfToken = "";
      var isAuthenticated = false;

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

      // Check current authentication status
      function checkAuthStatus() {
        fetch("/auth/me", { credentials: "same-origin" })
          .then(function(res) { return res.json(); })
          .then(function(data) {
            if (data.authenticated && data.user) {
              isAuthenticated = true;
              currentCsrfToken = data.csrf_token || "";
              userEmailDisplay.textContent = data.user.email || "Authenticated User";
              authBanner.style.display = "flex";
              unauthBanner.style.display = "none";
              analyseBtn.textContent = "Analyse URL";
            } else {
              isAuthenticated = false;
              currentCsrfToken = "";
              authBanner.style.display = "none";
              unauthBanner.style.display = "flex";
              analyseBtn.textContent = "Sign in to Analyse";
            }
          })
          .catch(function() {
            isAuthenticated = false;
            authBanner.style.display = "none";
            unauthBanner.style.display = "flex";
          });
      }

      checkAuthStatus();

      // Logout interaction: POST only with CSRF protection
      if (logoutBtn) {
        logoutBtn.addEventListener("click", function() {
          logoutBtn.disabled = true;
          fetch("/auth/logout", {
            method: "POST",
            headers: {
              "X-CSRF-Token": currentCsrfToken
            },
            credentials: "same-origin"
          })
          .then(function() {
            window.location.reload();
          })
          .catch(function() {
            window.location.reload();
          });
        });
      }

      analyseBtn.addEventListener("click", function() {
        hideError();
        resultSection.style.display = "none";

        if (!isAuthenticated) {
          window.location.href = "/auth/login";
          return;
        }

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
            "X-CSRF-Token": currentCsrfToken
          },
          credentials: "same-origin",
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

          if (payload.status === 401) {
            isAuthenticated = false;
            checkAuthStatus();
            showError("Authentication session expired. Please sign in with Google.");
            return;
          }

          if (payload.status === 403) {
            showError("CSRF verification failed. Please refresh the page and try again.");
            return;
          }

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
