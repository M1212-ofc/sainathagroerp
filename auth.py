"""Authentication + per-user permission control."""
import json
from functools import wraps
from flask import session, redirect, url_for, flash

# All grantable modules (order = display order in Users checkboxes)
ALL_MODULES = [
    ("dash_production", "Production Dashboard"),
    ("dash_main",       "Main Dashboard (financial)"),
    ("production",      "Production entry/edit"),
    ("procurement",     "Procurement"),
    ("inventory",       "Inventory"),
    ("sales",           "Sales & Export"),
    ("waste",           "Waste"),
    ("finance",         "Finance"),
    ("masters",         "Masters"),
    ("users",           "User management"),
]
MODULE_KEYS = [k for k, _ in ALL_MODULES]

# Role templates: default permission set applied when a user is created.
ROLE_TEMPLATES = {
    "owner": MODULE_KEYS[:],
    "manager": ["dash_production", "production", "procurement", "inventory",
                "sales", "waste", "masters"],
    "accountant": ["dash_main", "finance", "sales", "procurement"],
    "operator": ["dash_production", "production"],
}


def template_for(role):
    return ROLE_TEMPLATES.get(role, ["dash_production"])[:]


def current_user():
    if "user_id" in session:
        return {
            "id": session["user_id"],
            "username": session.get("username"),
            "full_name": session.get("full_name"),
            "role": session.get("role"),
            "perms": session.get("perms", []),
        }
    return None


def user_perms():
    return set(session.get("perms", []))


def can_access(module, write=True):
    """Owner always full. Otherwise check the per-user permission list."""
    if session.get("role") == "owner":
        return True
    return module in user_perms()


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def require(module, write=True):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if not can_access(module, write=write):
                flash("You don't have permission for that.", "err")
                return redirect(url_for("home"))
            return f(*a, **kw)
        return wrapper
    return deco


def load_perms(row):
    """Given a users row, return the effective permission list."""
    keys = row.keys()
    raw = (row["permissions"] or "").strip() if "permissions" in keys else ""
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    return template_for(row["role"])
