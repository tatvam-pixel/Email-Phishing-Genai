# PhishGuard AI

Phishing and suspicious URL detector.

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

- API Docs: `http://localhost:8000/docs`
- OpenAPI Spec: `http://localhost:8000/openapi.json`
- Health check: `http://localhost:8000/api/v1/health`

## Vercel Deployment

1. Import repo into Vercel.
2. In Project Settings > General, set **Root Directory** to `backend`.
3. Set environment variable: `ENV=production` (no secrets needed for skeleton).
4. Deploy; check that live `https://<deployment-url>/api/v1/health` returns HTTP 200.
