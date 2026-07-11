import sys, os
project_home = "/home/sainathagro/sainath_erp"
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# --- Optional: daily email backup config (see README) ---
# os.environ["BACKUP_EMAIL_TO"]   = "you@example.com"
# os.environ["BACKUP_EMAIL_FROM"] = "you@example.com"
# os.environ["BREVO_API_KEY"]     = "your-brevo-key"

from app import app as application
