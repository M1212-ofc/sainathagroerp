"""
SAINATH AGRO INDUSTRIES - ERP
Database schema + initialization.

Modules: auth/users, daily production (crushing & cleaning separate),
procurement (raw material in), inventory (raw + finished), sales, exports,
waste, finance (income/expense), currencies.
"""
import os
import sqlite3
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "sainath_erp.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
-- ------------------------------------------------------------------ USERS
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    full_name     TEXT,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'operator',   -- owner|manager|accountant|operator
    permissions   TEXT DEFAULT '',        -- JSON list of granted module keys (per-user override)
    active        INTEGER DEFAULT 1,
    created_at    TEXT DEFAULT (datetime('now'))
);

-- --------------------------------------------------------------- CURRENCIES
CREATE TABLE IF NOT EXISTS currencies (
    code      TEXT PRIMARY KEY,      -- INR, USD, EUR ...
    symbol    TEXT,
    rate_to_inr REAL DEFAULT 1        -- 1 unit of this currency = X INR
);

-- --------------------------------------------------------------- PRODUCTS
-- Finished goods catalog (Corn Cob Powder, Grits, Bhunar, Walnut, etc.)
CREATE TABLE IF NOT EXISTS products (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL,
    category  TEXT,                  -- crushing | cleaning | other
    unit      TEXT DEFAULT 'kg',
    low_stock REAL DEFAULT 0,        -- alert threshold
    sell_rate REAL DEFAULT 0,        -- avg selling rate ₹/kg (for inventory valuation)
    active    INTEGER DEFAULT 1
);

-- ------------------------------------------------------------ RAW MATERIALS
CREATE TABLE IF NOT EXISTS raw_materials (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name    TEXT NOT NULL,           -- Corn Cob, Walnut Shell, Maize ...
    unit    TEXT DEFAULT 'kg',
    low_stock REAL DEFAULT 0,        -- alert threshold
    active  INTEGER DEFAULT 1
);

-- ------------------------------------------------------------- SUPPLIERS
CREATE TABLE IF NOT EXISTS suppliers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    company_name  TEXT,
    village       TEXT,
    address       TEXT,
    contact_name  TEXT,
    phone_cc      TEXT DEFAULT '+91',
    phone         TEXT,
    gst_no        TEXT,
    email         TEXT,
    notes         TEXT,
    custom        TEXT DEFAULT '{}'      -- JSON of custom field values
);

-- --------------------------------------------------------------- CUSTOMERS
CREATE TABLE IF NOT EXISTS customers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    company_name  TEXT,
    kind          TEXT DEFAULT 'domestic',   -- domestic | export
    address       TEXT,
    contact_name  TEXT,
    phone_cc      TEXT DEFAULT '+91',
    phone         TEXT,
    gst_no        TEXT,
    country       TEXT,
    city          TEXT,
    email         TEXT,
    vehicle_no    TEXT,                      -- default transport vehicle
    notes         TEXT,
    custom        TEXT DEFAULT '{}'
);

-- ------------------------------------------------ CUSTOM FIELD DEFINITIONS
-- User-defined extra fields per entity (customer|supplier|product|raw_material)
CREATE TABLE IF NOT EXISTS custom_fields (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    entity    TEXT NOT NULL,          -- customer|supplier|product|raw_material
    field_key TEXT NOT NULL,          -- machine name
    label     TEXT NOT NULL,          -- display label
    ftype     TEXT DEFAULT 'text',    -- text|number|date|select
    options   TEXT,                   -- comma-separated for select
    required  INTEGER DEFAULT 0,
    sort      INTEGER DEFAULT 0,
    UNIQUE(entity, field_key)
);

-- ------------------------------------------------ DASHBOARD LAYOUTS (per user)
CREATE TABLE IF NOT EXISTS dashboard_layouts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL,
    variant   TEXT NOT NULL,          -- main | production
    layout    TEXT NOT NULL,          -- JSON: list of widgets [{id,metric,type,size,hidden}]
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, variant)
);

-- ------------------------------------------------------ DAILY PRODUCTION
CREATE TABLE IF NOT EXISTS reports (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    report_date          TEXT NOT NULL,
    shift                TEXT NOT NULL,          -- Day | Night
    start_unit           REAL,
    close_unit           REAL,
    consumption          REAL,
    persons_m1           INTEGER DEFAULT 0,
    persons_m2           INTEGER DEFAULT 0,
    reel                 INTEGER DEFAULT 0,
    on_time              TEXT,
    off_time             TEXT,
    raw_buckets          INTEGER DEFAULT 0,
    bucket_weight        REAL DEFAULT 25,
    raw_output_kg        REAL DEFAULT 0,
    crushing_total_theli REAL DEFAULT 0,
    crushing_total_kg    REAL DEFAULT 0,
    cleaning_total_theli REAL DEFAULT 0,
    cleaning_total_kg    REAL DEFAULT 0,
    waste_kg             REAL DEFAULT 0,         -- waste/reject from this shift
    light_gayi_time      TEXT,
    loading_powder       TEXT,
    loading_grit         TEXT,
    loading_bhunar       TEXT,
    maintenance          TEXT,
    other_maint_cost     REAL DEFAULT 0,
    left_with_note       INTEGER DEFAULT 0,
    half_attendance      TEXT,
    on_leave_names       TEXT,
    reporter             TEXT,
    office               TEXT,
    notes                TEXT,
    created_by           INTEGER,
    created_at           TEXT DEFAULT (datetime('now')),
    UNIQUE(report_date, shift)
);

CREATE TABLE IF NOT EXISTS production_lines (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id    INTEGER NOT NULL,
    category     TEXT NOT NULL,          -- crushing | cleaning
    name         TEXT NOT NULL,
    theli        REAL DEFAULT 0,
    theli_weight REAL DEFAULT 0,
    total_kg     REAL DEFAULT 0,
    FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS workers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id  INTEGER NOT NULL,
    slno       INTEGER,
    name       TEXT,
    worker_id  INTEGER,                 -- links to worker_master.id
    attendance TEXT DEFAULT 'present',  -- present | absent | half
    hours      REAL DEFAULT 0,          -- custom hours worked
    ot_hours   REAL DEFAULT 0,          -- overtime hours
    machine_id INTEGER,                 -- which machine this worker was on
    FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE
);

-- ------------------------------------------------------- MACHINE MASTER
CREATE TABLE IF NOT EXISTS machine_master (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    capacity_kg   REAL DEFAULT 0,        -- rated output per day
    power_kw      REAL DEFAULT 0,        -- rated power draw
    note          TEXT,
    active        INTEGER DEFAULT 1
);

-- ------------------------------------------------------- MACHINE DAILY LOG
CREATE TABLE IF NOT EXISTS machine_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id     INTEGER,              -- links to reports.id (production entry)
    log_date      TEXT NOT NULL,
    machine_id    INTEGER NOT NULL,
    machine_name  TEXT,
    output_kg     REAL DEFAULT 0,
    units         REAL DEFAULT 0,       -- electricity units consumed
    labour_cost   REAL DEFAULT 0,
    maint_cost    REAL DEFAULT 0,
    note          TEXT,
    created_at    TEXT DEFAULT (datetime('now'))
);

-- ------------------------------------------------------- WORKER MASTER
CREATE TABLE IF NOT EXISTS worker_master (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    phone         TEXT,
    role          TEXT,                 -- machine operator, helper, etc.
    default_hours REAL DEFAULT 12,      -- default shift hours
    pay_type      TEXT DEFAULT 'daily', -- daily | monthly
    pay_rate      REAL DEFAULT 0,       -- daily rate OR monthly salary
    ot_rate       REAL DEFAULT 0,       -- overtime rate per hour (0 = no OT)
    active        INTEGER DEFAULT 1
);

-- ------------------------------------------------------- ELECTRICITY BILLS
CREATE TABLE IF NOT EXISTS solar_daily (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    log_date    TEXT NOT NULL,
    units       REAL DEFAULT 0,
    note        TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(log_date)
);

CREATE TABLE IF NOT EXISTS electricity_bills (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    month         TEXT NOT NULL,          -- YYYY-MM
    amount_inr    REAL NOT NULL,
    units         REAL DEFAULT 0,         -- optional: MGVCL units billed
    rate_per_unit REAL DEFAULT 0,         -- ₹ per unit (manual or suggested)
    solar_units   REAL DEFAULT 0,         -- solar units generated this month
    note          TEXT,
    created_at    TEXT DEFAULT (datetime('now')),
    UNIQUE(month)
);

-- ------------------------------------------------------- WORKER ADVANCES (UDHAR)
CREATE TABLE IF NOT EXISTS worker_advances (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_id   INTEGER NOT NULL,
    entry_date  TEXT NOT NULL,
    kind        TEXT NOT NULL,           -- 'given' (advance out) | 'repaid' (worker pays back)
    amount      REAL NOT NULL DEFAULT 0,
    note        TEXT,
    created_by  INTEGER,
    created_at  TEXT DEFAULT (datetime('now'))
);

-- ------------------------------------------------------- WAGE ADJUSTMENTS
CREATE TABLE IF NOT EXISTS wage_adjustments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    month       TEXT NOT NULL,           -- YYYY-MM
    worker_id   INTEGER NOT NULL,
    amount      REAL DEFAULT 0,          -- +bonus / -deduction
    note        TEXT,
    UNIQUE(month, worker_id)
);

-- ------------------------------------------------------- PAYMENTS LOG
CREATE TABLE IF NOT EXISTS payments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pay_date    TEXT NOT NULL,
    party_type  TEXT,                   -- customer | supplier
    party_id    INTEGER,
    party_name  TEXT,
    direction   TEXT,                   -- in (received) | out (paid)
    amount_inr  REAL NOT NULL,
    method      TEXT,                   -- cash | bank | upi | cheque
    ref_id      INTEGER,                -- optional link to sale/procurement
    note        TEXT,
    created_by  INTEGER,
    created_at  TEXT DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------- PROCUREMENT
-- Raw material arriving (village, supplier, transport, weight, rate)
CREATE TABLE IF NOT EXISTS procurement (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_date     TEXT NOT NULL,
    supplier_id    INTEGER,
    village        TEXT,
    raw_material_id INTEGER,
    transport      TEXT,               -- tractor | truck | container | other
    vehicle_no     TEXT,
    quantity_kg    REAL DEFAULT 0,
    rate_per_kg    REAL DEFAULT 0,
    freight_cost   REAL DEFAULT 0,
    total_cost     REAL DEFAULT 0,     -- quantity*rate + freight
    paid           REAL DEFAULT 0,
    notes          TEXT,
    created_by     INTEGER,
    created_at     TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(supplier_id) REFERENCES suppliers(id),
    FOREIGN KEY(raw_material_id) REFERENCES raw_materials(id)
);

-- ------------------------------------------------------------- SALES
CREATE TABLE IF NOT EXISTS sales (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_date     TEXT NOT NULL,
    kind          TEXT DEFAULT 'domestic',   -- domestic | export
    customer_id   INTEGER,
    product_id    INTEGER,
    quantity_kg   REAL DEFAULT 0,
    rate          REAL DEFAULT 0,            -- per kg in the sale currency
    goods_cost    REAL DEFAULT 0,            -- quantity * rate (before tax/freight)
    tax_pct       REAL DEFAULT 0,            -- tax percentage
    tax_amount    REAL DEFAULT 0,            -- computed tax
    currency      TEXT DEFAULT 'INR',
    fx_rate       REAL DEFAULT 1,            -- currency -> INR at sale time
    freight_cost  REAL DEFAULT 0,
    other_cost    REAL DEFAULT 0,
    total_amount  REAL DEFAULT 0,            -- in sale currency
    total_inr     REAL DEFAULT 0,            -- converted to INR
    received      REAL DEFAULT 0,            -- amount received (sale currency)
    invoice_no    TEXT,
    vehicle_no    TEXT,                      -- transport vehicle number
    -- export-specific
    port          TEXT,
    container_no  TEXT,
    hs_code       TEXT,
    notes         TEXT,
    created_by    INTEGER,
    created_at    TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(customer_id) REFERENCES customers(id),
    FOREIGN KEY(product_id) REFERENCES products(id)
);

-- ----------------------------------------------------- INVENTORY MOVEMENTS
-- Unified ledger for raw + finished. +qty = in, -qty = out.
CREATE TABLE IF NOT EXISTS inventory_moves (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    move_date   TEXT NOT NULL,
    item_type   TEXT NOT NULL,        -- raw | finished
    item_id     INTEGER NOT NULL,     -- raw_materials.id or products.id
    item_name   TEXT,                 -- denormalized for easy display
    qty_kg      REAL NOT NULL,        -- signed
    source      TEXT,                 -- production|procurement|sale|manual|waste
    ref_id      INTEGER,              -- id in source table
    note        TEXT,
    created_by  INTEGER,
    created_at  TEXT DEFAULT (datetime('now'))
);

-- --------------------------------------------------------------- FINANCE
-- Generic income/expense ledger; sales & procurement also post here.
CREATE TABLE IF NOT EXISTS finance (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_date  TEXT NOT NULL,
    direction   TEXT NOT NULL,        -- income | expense
    category    TEXT,                 -- sales|export|raw_material|freight|salary|electricity|maintenance|other
    amount_inr  REAL NOT NULL,
    currency    TEXT DEFAULT 'INR',
    fx_rate     REAL DEFAULT 1,
    amount_orig REAL,
    source      TEXT,                 -- sale|procurement|manual
    ref_id      INTEGER,
    description TEXT,
    created_by  INTEGER,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS waste (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    waste_date  TEXT NOT NULL,
    source      TEXT,                 -- production|cleaning|manual
    material    TEXT,
    quantity_kg REAL DEFAULT 0,
    disposal    TEXT,                 -- sold|dumped|reused
    value_inr   REAL DEFAULT 0,       -- recovered value if sold
    notes       TEXT,
    created_by  INTEGER,
    created_at  TEXT DEFAULT (datetime('now'))
);
"""


def init_db(seed=True):
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    # ---- performance indexes (speed up date-range & lookup queries) ----
    conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_reports_date ON reports(report_date);
        CREATE INDEX IF NOT EXISTS idx_lines_report ON production_lines(report_id);
        CREATE INDEX IF NOT EXISTS idx_workers_report ON workers(report_id);
        CREATE INDEX IF NOT EXISTS idx_sales_date ON sales(sale_date);
        CREATE INDEX IF NOT EXISTS idx_proc_date ON procurement(entry_date);
        CREATE INDEX IF NOT EXISTS idx_moves_item ON inventory_moves(item_type, item_name);
        CREATE INDEX IF NOT EXISTS idx_moves_src ON inventory_moves(source, ref_id);
        CREATE INDEX IF NOT EXISTS idx_finance_date ON finance(entry_date);
        CREATE INDEX IF NOT EXISTS idx_waste_date ON waste(waste_date);
    """)
    conn.commit()
    # WAL mode = faster concurrent reads/writes
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
    except Exception:
        pass
    conn.commit()

    if seed:
        _seed_defaults(conn)
    conn.close()


def _seed_defaults(conn):
    from werkzeug.security import generate_password_hash

    # default owner account
    cur = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if cur == 0:
        conn.execute(
            "INSERT INTO users (username, full_name, password_hash, role) VALUES (?,?,?,?)",
            ("admin", "Owner", generate_password_hash("admin123"), "owner"),
        )

    # currencies
    if conn.execute("SELECT COUNT(*) FROM currencies").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO currencies (code, symbol, rate_to_inr) VALUES (?,?,?)",
            [("INR", "₹", 1), ("USD", "$", 83.0), ("EUR", "€", 90.0),
             ("GBP", "£", 105.0), ("AED", "د.إ", 22.6)],
        )

    # products (from the website + daily sheet)
    if conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO products (name, category) VALUES (?,?)",
            [
                ("Corn Cob Powder", "crushing"),
                ("Corn Cob Grits", "cleaning"),
                ("Corn Cob Granules", "cleaning"),
                ("Corn Cob Animal Bedding", "cleaning"),
                ("Grit No. 1", "cleaning"),
                ("Grit No. 2", "cleaning"),
                ("Grit No. 3", "cleaning"),
                ("Grit No. 4", "cleaning"),
                ("Bhunar (Fines)", "cleaning"),
                ("Walnut Shell Grit", "cleaning"),
                ("Walnut Shell Powder", "crushing"),
                ("Yellow Maize", "other"),
            ],
        )

    # raw materials
    if conn.execute("SELECT COUNT(*) FROM raw_materials").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO raw_materials (name) VALUES (?)",
            [("Corn Cob",), ("Walnut Shell",), ("Yellow Maize",), ("Corn Stem",)],
        )

    conn.commit()


if __name__ == "__main__":
    init_db()
    print("DB initialized at", DB_PATH)
