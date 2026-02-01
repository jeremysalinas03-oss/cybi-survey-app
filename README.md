# CYBI Survey (Render + PostgreSQL)

## What this repo is
A secure Flask survey app that stores results in **Render PostgreSQL**.

### Features
- CSRF tokenization
- /results + /export_csv protected by ADMIN_PASSWORD (Basic Auth)
- Optional rate limiting
- Security headers
- PostgreSQL auto-init at startup

## Render setup
1) Create Render **PostgreSQL** (you already did).
2) Create Render **Web Service** from this repo.
3) Set environment variables in the Web Service:
   - DATABASE_URL = Internal Database URL (from Render Postgres)
   - SECRET_KEY = long random string
   - ADMIN_PASSWORD = strong password
   - COOKIE_SECURE = 1

Start command is in Procfile:
- `gunicorn app:app`

## Local run (optional)
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Example (use *External Database URL* if running locally)
export DATABASE_URL="postgresql://..."
export SECRET_KEY="dev-secret"
export ADMIN_PASSWORD="admin"
# Leave COOKIE_SECURE unset for local HTTP
python app.py
```

Open:
- http://127.0.0.1:5000/
- http://127.0.0.1:5000/results
