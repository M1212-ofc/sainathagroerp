"""Business logic: inventory ledger, finance ledger, stock levels."""
from models import get_conn


def post_inventory(conn, move_date, item_type, item_id, item_name, qty_kg,
                   source, ref_id=None, note=None, user_id=None):
    conn.execute(
        """INSERT INTO inventory_moves
           (move_date, item_type, item_id, item_name, qty_kg, source, ref_id, note, created_by)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (move_date, item_type, item_id, item_name, qty_kg, source, ref_id, note, user_id),
    )


def post_finance(conn, entry_date, direction, category, amount_inr,
                 currency="INR", fx_rate=1, amount_orig=None,
                 source="manual", ref_id=None, description=None, user_id=None):
    conn.execute(
        """INSERT INTO finance
           (entry_date, direction, category, amount_inr, currency, fx_rate,
            amount_orig, source, ref_id, description, created_by)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (entry_date, direction, category, amount_inr, currency, fx_rate,
         amount_orig, source, ref_id, description, user_id),
    )


def clear_source(conn, table, source, ref_id):
    """Remove prior auto-posted rows for a source ref (used on edit/delete)."""
    conn.execute(f"DELETE FROM {table} WHERE source=? AND ref_id=?", (source, ref_id))


def stock_levels(conn):
    """Return current stock for raw + finished from the moves ledger.
    Group by item_name so every distinct product/material shows its own row
    (production may post finished goods with item_id=0 when name isn't in the
    catalog, which previously collapsed them all into one row)."""
    rows = conn.execute(
        """SELECT item_type, MAX(item_id) AS item_id, item_name, SUM(qty_kg) AS qty
           FROM inventory_moves
           GROUP BY item_type, item_name
           HAVING ABS(SUM(qty_kg)) > 0.0001
           ORDER BY item_type, item_name"""
    ).fetchall()
    raw = [dict(r) for r in rows if r["item_type"] == "raw"]
    finished = [dict(r) for r in rows if r["item_type"] == "finished"]
    return raw, finished


def stock_for(conn, item_type, item_name):
    """Current stock (kg) for a specific item by name."""
    r = conn.execute(
        "SELECT COALESCE(SUM(qty_kg),0) FROM inventory_moves WHERE item_type=? AND item_name=?",
        (item_type, item_name)).fetchone()
    return round(r[0] or 0, 2)


def stock_for_raw_id(conn, raw_id):
    """Current stock for a raw material by its id (matches on its name)."""
    m = conn.execute("SELECT name FROM raw_materials WHERE id=?", (raw_id,)).fetchone()
    if not m:
        return 0
    return stock_for(conn, "raw", m["name"])


def low_stock_alerts(conn):
    """Return items at/below their configured low_stock threshold (threshold>0)."""
    raw, finished = stock_levels(conn)
    stock_map = {}
    for i in raw:
        stock_map[("raw", i["item_name"])] = i["qty"]
    for i in finished:
        stock_map[("finished", i["item_name"])] = i["qty"]
    alerts = []
    for m in conn.execute("SELECT name, low_stock FROM raw_materials WHERE low_stock>0").fetchall():
        qty = stock_map.get(("raw", m["name"]), 0)
        if qty <= m["low_stock"]:
            alerts.append(dict(type="raw", name=m["name"], qty=round(qty, 2), threshold=m["low_stock"]))
    for p in conn.execute("SELECT name, low_stock FROM products WHERE low_stock>0").fetchall():
        qty = stock_map.get(("finished", p["name"]), 0)
        if qty <= p["low_stock"]:
            alerts.append(dict(type="finished", name=p["name"], qty=round(qty, 2), threshold=p["low_stock"]))
    return alerts


def finance_summary(conn, start, end):
    """Income, expense, profit in INR for a date range, plus category breakdown."""
    inc = conn.execute(
        "SELECT COALESCE(SUM(amount_inr),0) FROM finance WHERE direction='income' AND entry_date BETWEEN ? AND ?",
        (start, end),
    ).fetchone()[0]
    exp = conn.execute(
        "SELECT COALESCE(SUM(amount_inr),0) FROM finance WHERE direction='expense' AND entry_date BETWEEN ? AND ?",
        (start, end),
    ).fetchone()[0]
    by_cat = conn.execute(
        """SELECT direction, category, COALESCE(SUM(amount_inr),0) AS amt
           FROM finance WHERE entry_date BETWEEN ? AND ?
           GROUP BY direction, category ORDER BY amt DESC""",
        (start, end),
    ).fetchall()
    return {
        "income": round(inc, 2),
        "expense": round(exp, 2),
        "profit": round(inc - exp, 2),
        "by_category": [dict(r) for r in by_cat],
    }
