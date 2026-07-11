"""
Backup module for Sainath Agro ERP.

- make_backup_zip(): dumps every table to CSV, returns (zip_bytes, filename).
- email_backup(): sends that zip to a configured address via the Brevo (Sendinblue)
  transactional email API over HTTPS — which works on PythonAnywhere's free
  outbound whitelist (SMTP does not).

Configuration via environment variables (set in the PythonAnywhere WSGI file
or a .env you load):
    BACKUP_EMAIL_TO      = where to send backups (your email)
    BREVO_API_KEY        = your Brevo API key (free tier: 300 emails/day)
    BACKUP_EMAIL_FROM    = verified sender in your Brevo account
    BACKUP_DIR           = optional folder to also save daily backups on disk
"""
import os
import io
import csv
import zipfile
import base64
import json
import sqlite3
import urllib.request
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "sainath_erp.db")

TABLES = [
    "users", "currencies", "products", "raw_materials", "suppliers", "customers",
    "custom_fields", "dashboard_layouts", "reports", "production_lines", "workers",
    "procurement", "sales", "inventory_moves", "finance", "waste",
]


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def make_backup_zip(exclude_sensitive=True):
    """Return (zip_bytes, filename). One CSV per table."""
    conn = _conn()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for t in TABLES:
            try:
                rows = conn.execute(f"SELECT * FROM {t}").fetchall()
            except sqlite3.OperationalError:
                continue  # table may not exist yet
            sbuf = io.StringIO()
            if rows:
                cols = rows[0].keys()
                # never export password hashes
                if exclude_sensitive and t == "users":
                    cols = [c for c in cols if c != "password_hash"]
                w = csv.writer(sbuf)
                w.writerow(cols)
                for r in rows:
                    w.writerow([r[c] for c in cols])
            else:
                sbuf.write("")  # empty table -> empty file
            z.writestr(f"{t}.csv", sbuf.getvalue())
        # a small manifest
        z.writestr("_manifest.txt",
                   f"Sainath Agro ERP backup\nGenerated: {datetime.now().isoformat()}\n"
                   f"Tables: {', '.join(TABLES)}\n")
    conn.close()
    fname = f"sainath_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    return buf.getvalue(), fname


def save_backup_to_disk():
    """Write a backup zip into BACKUP_DIR (if configured). Returns path or None."""
    folder = os.environ.get("BACKUP_DIR")
    if not folder:
        folder = os.path.join(BASE_DIR, "backups")
    os.makedirs(folder, exist_ok=True)
    data, fname = make_backup_zip()
    path = os.path.join(folder, fname)
    with open(path, "wb") as f:
        f.write(data)
    # keep only the latest 30 backups
    files = sorted(
        [os.path.join(folder, x) for x in os.listdir(folder) if x.endswith(".zip")])
    for old in files[:-30]:
        try:
            os.remove(old)
        except OSError:
            pass
    return path


def email_backup():
    """Email the backup zip via Brevo API. Returns (ok, message)."""
    to_addr = os.environ.get("BACKUP_EMAIL_TO")
    api_key = os.environ.get("BREVO_API_KEY")
    from_addr = os.environ.get("BACKUP_EMAIL_FROM", to_addr)
    if not to_addr or not api_key:
        return False, "BACKUP_EMAIL_TO / BREVO_API_KEY not configured."

    data, fname = make_backup_zip()
    payload = {
        "sender": {"email": from_addr, "name": "Sainath Agro ERP"},
        "to": [{"email": to_addr}],
        "subject": f"Sainath Agro ERP backup — {datetime.now().strftime('%d %b %Y')}",
        "htmlContent": (
            "<p>Attached is the automatic daily backup of the Sainath Agro ERP "
            "database (one CSV per table, zipped).</p>"
            f"<p>Generated: {datetime.now().strftime('%d %b %Y %H:%M')}</p>"),
        "attachment": [{
            "content": base64.b64encode(data).decode(),
            "name": fname,
        }],
    }
    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=json.dumps(payload).encode(),
        headers={"api-key": api_key, "Content-Type": "application/json",
                 "accept": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status in (200, 201):
                return True, "Backup emailed."
            return False, f"Email API returned {resp.status}"
    except Exception as ex:
        return False, f"Email failed: {ex}"


if __name__ == "__main__":
    # Used by the daily scheduled task on PythonAnywhere
    path = save_backup_to_disk()
    print("Saved backup:", path)
    ok, msg = email_backup()
    print("Email:", ok, msg)
