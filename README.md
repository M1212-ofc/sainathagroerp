# SAINATH AGRO INDUSTRIES — ERP

Flask + SQLite operations & finance app: role-based login with per-user
permissions, two dashboards (Production / Main), daily production, procurement,
inventory, sales & exports, waste, finance/P&L, masters with custom fields,
and automatic backups.

## Login
Default owner: **admin / admin123** — change it under Users after first login.

## Run locally (Windows)
```
pip install -r requirements.txt
python app.py
```
Open http://localhost:5000

------------------------------------------------------------------------
## Deploy on PythonAnywhere (free tier)

1. Push this folder to GitHub (you already have: github.com/M1212-ofc/sainathagroerp).
2. On PythonAnywhere open a **Bash console** and clone:
   ```
   git clone https://github.com/M1212-ofc/sainathagroerp.git sainath_erp
   pip install --user flask werkzeug
   ```
   (To update later: `cd sainath_erp && git pull`.)
3. **Web tab → Add a new web app → Manual configuration → Python 3.x**.
4. Source code: `/home/sainathagro/sainath_erp`
5. Edit the **WSGI configuration file**, replace contents with:
   ```python
   import sys, os
   project_home = "/home/sainathagro/sainath_erp"
   if project_home not in sys.path:
       sys.path.insert(0, project_home)
   # --- backup email config (optional, see below) ---
   os.environ["BACKUP_EMAIL_TO"]   = "you@example.com"
   os.environ["BACKUP_EMAIL_FROM"] = "you@example.com"
   os.environ["BREVO_API_KEY"]     = "your-brevo-key"
   from app import app as application
   ```
6. **Static files**: URL `/static/` → Directory `/home/sainathagro/sainath_erp/static/`
7. Click **Reload**. Visit `sainathagro.pythonanywhere.com`.

The SQLite database `sainath_erp.db` is created automatically on first run.
IMPORTANT: change `app.secret_key` in app.py to a random string.

------------------------------------------------------------------------
## Backups

### Manual (any time)
Log in as Owner → **Backup** in the sidebar → **Download Backup Now**.
You get a ZIP with one CSV per table (opens in Excel).

### Daily automatic email backup (free)
Uses the **Brevo** email API (free: 300 emails/day) which works on
PythonAnywhere's free outbound whitelist (normal SMTP does not).

1. Create a free account at brevo.com. Verify a sender email.
   Get an API key (SMTP & API → API Keys).
2. Put these in the WSGI file (step 5 above): `BACKUP_EMAIL_TO`,
   `BACKUP_EMAIL_FROM`, `BREVO_API_KEY`.
3. Add the daily domain to PythonAnywhere's whitelist request if needed
   (api.brevo.com is generally reachable).
4. **Tasks tab → add a Scheduled task** (free = one daily task):
   ```
   python3 /home/sainathagro/sainath_erp/backup.py
   ```
   Set the time (e.g. 23:30). This emails the backup AND saves a copy in
   the server `backups/` folder (latest 30 kept).

Test it immediately from Owner → Backup → **Email Backup Now**.

------------------------------------------------------------------------
## Roles & permissions
Owner (full + users + backup), Manager, Accountant, Operator — each with
per-user permission checkboxes (Users page). Roles are starting templates.

## Modules
Two dashboards (customizable widgets, saved to your account), Production
(your daily sheet), Procurement (auto-deducts nothing / adds raw stock),
Inventory (raw + finished, auto + manual), Sales & Export (tax, multi-currency,
two totals), Waste, Finance (auto-posted P&L), Masters (+ custom fields), Users.
