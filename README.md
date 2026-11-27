# PhishGuard AI

Phishing and suspicious URL detector.

## Prototype Demo

A demo-ready prototype featuring structural URL threat evaluation (Lite policy rules U01–U12, N01), Gemini AI explanations grounded in backend evidence, OpenAPI documentation, Google OAuth 2.0 authentication, and a self-contained web interface.

### Environment Variables

| Variable | Description | Example |
|---|---|---|
| `DEMO_API_KEY_SHA256` | SHA-256 hex digest of the authorized demo API key | Hex string |
| `GEMINI_API_KEY` | Google Gemini API key for AI threat explanations | `AIza...` |
| `GEMINI_MODEL` | Gemini model name (defaults to `gemini-2.5-flash`) | `gemini-2.5-flash` |
| `GOOGLE_CLIENT_ID` | Google OAuth 2.0 Web Client ID | `*.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET` | Google OAuth 2.0 Web Client Secret | String |
| `GOOGLE_REDIRECT_URI` | Configured OAuth redirect URI | `http://localhost:8000/auth/callback` |
| `SESSION_SECRET` | Secret key for signed session cookies and CSRF HMAC tokens | Random 32+ byte string |

To generate a session secret or demo key:

```powershell
python -c "import secrets; print('SESSION_SECRET:', secrets.token_hex(32))"
python -c "import secrets, hashlib; k='pg_demo_'+secrets.token_urlsafe(16); print('API Key:', k); print('DEMO_API_KEY_SHA256:', hashlib.sha256(k.encode()).hexdigest())"
```

### Google Cloud Console Setup

1. In [Google Cloud Console](https://console.cloud.google.com/), create or select a project.
2. Configure the **OAuth Consent Screen** (User Type: External, scope: `openid`, `email`, `profile`).
3. Under **Credentials**, create an **OAuth 2.0 Client ID** (Application type: *Web application*).
4. Add **Authorized redirect URIs**:
   - Local: `http://localhost:8000/auth/callback`
   - Production: `https://<your-vercel-domain>.vercel.app/auth/callback`
5. Copy the **Client ID** and **Client Secret** into your environment variables.

### Running Locally

```powershell
cd backend
$env:SESSION_SECRET = "<session-secret>"
$env:GOOGLE_CLIENT_ID = "<google-client-id>"
$env:GOOGLE_CLIENT_SECRET = "<google-client-secret>"
$env:GOOGLE_REDIRECT_URI = "http://localhost:8000/auth/callback"
$env:DEMO_API_KEY_SHA256 = "<sha256-hash>"
$env:GEMINI_API_KEY = "<gemini-api-key>"
$env:GEMINI_MODEL = "gemini-2.5-flash"
flask --app app run --port 8000
```

- Web UI: `http://localhost:8000/`
- Interactive API Docs: `http://localhost:8000/docs`
- OpenAPI Specification: `http://localhost:8000/openapi.json`
- Health check: `http://localhost:8000/api/v1/health`

### Dual Authentication

1. **Browser (Session & CSRF):**
   - Click "Continue with Google" at `/auth/login` to sign in.
   - Upon successful OIDC verification (issuer, audience, signature, expiration, nonce), an `HttpOnly`, `SameSite=Lax` session cookie is issued.
   - State-changing API requests (e.g. `POST /api/v1/scan/url`) require a cryptographically signed `X-CSRF-Token` header bound to the authenticated user.
2. **Programmatic (API Key):**
   - Clients send `X-API-Key: <key>` header.
   - Authentication paths are independent: valid API-key requests explicitly bypass CSRF; invalid API keys immediately return 401 with no session fallback.

### Curl Example (Programmatic)

```bash
curl -X POST http://localhost:8000/api/v1/scan/url \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-demo-api-key>" \
  -d '{"url": "http://paypal.secure-login.verify-account.xyz/update", "include_ai_analysis": true}'
```

## Local Development (Backend)

Run from Windows PowerShell:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pytest tests/ -v
flask --app app run --port 8000
```

## Vercel Deployment

1. Import repo into Vercel.
2. In Project Settings > General, set **Root Directory** to `backend`.
3. Set environment variables:
   - `ENV=production`
   - `SESSION_SECRET`
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`
   - `GOOGLE_REDIRECT_URI`
   - `DEMO_API_KEY_SHA256`
   - `GEMINI_API_KEY`
   - `GEMINI_MODEL`
4. Deploy; verify that `https://<deployment-url>/api/v1/health` and `/` respond.
