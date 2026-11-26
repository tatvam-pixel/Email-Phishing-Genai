# PhishGuard AI

Phishing and suspicious URL detector.

## Prototype Demo

A demo-ready prototype featuring structural URL threat evaluation (Lite policy rules U01–U12, N01), Gemini AI explanations grounded in backend evidence, OpenAPI documentation, and a self-contained web interface.

### Environment Variables

| Variable | Description | Example |
|---|---|---|
| `DEMO_API_KEY_SHA256` | SHA-256 hex digest of the authorized demo API key | Hex string |
| `GEMINI_API_KEY` | Google Gemini API key for AI threat explanations | `AIza...` |
| `GEMINI_MODEL` | Gemini model name (defaults to `gemini-2.5-flash`) | `gemini-2.5-flash` |

To generate a demo key and its SHA-256 hash:

```powershell
python -c "import secrets, hashlib; k='pg_demo_'+secrets.token_urlsafe(16); print('API Key:', k); print('DEMO_API_KEY_SHA256:', hashlib.sha256(k.encode()).hexdigest())"
```

### Running Locally

```powershell
cd backend
$env:DEMO_API_KEY_SHA256 = "<sha256-hash>"
$env:GEMINI_API_KEY = "<gemini-api-key>"
$env:GEMINI_MODEL = "gemini-2.5-flash"
flask --app app run --port 8000
```

- Web UI: `http://localhost:8000/`
- Interactive API Docs: `http://localhost:8000/docs`
- OpenAPI Specification: `http://localhost:8000/openapi.json`
- Health check: `http://localhost:8000/api/v1/health`

### Curl Example

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
pip install -r requirements-dev.txt
pytest tests/ -v
flask --app app run --port 8000
```

## Vercel Deployment

1. Import repo into Vercel.
2. In Project Settings > General, set **Root Directory** to `backend`.
3. Set environment variables: `ENV=production`, `DEMO_API_KEY_SHA256`, `GEMINI_API_KEY`, `GEMINI_MODEL`.
4. Deploy; check that live `https://<deployment-url>/api/v1/health` and `/` respond.
