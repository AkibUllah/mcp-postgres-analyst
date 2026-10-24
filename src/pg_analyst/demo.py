"""Deterministic demo database: a fictional Bangladeshi online shop.

The same generator seeds SQLite (default, zero setup) and PostgreSQL (docker compose), so every
example in the README returns the same numbers on both.
"""

from __future__ import annotations

import hashlib
import random
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    comment: str


@dataclass(frozen=True)
class Table:
    name: str
    comment: str
    columns: tuple[Column, ...]
    constraints: tuple[str, ...] = ()


SCHEMA: tuple[Table, ...] = (
    Table(
        "customers",
        "Registered shoppers",
        (
            Column("id", "INTEGER PRIMARY KEY", "Customer id"),
            Column("full_name", "TEXT NOT NULL", "Name as entered at sign-up"),
            Column("email", "TEXT NOT NULL UNIQUE", "Login and receipt email address"),
            Column("phone", "TEXT NOT NULL", "Mobile number in +880 format, used for OTP"),
            Column("nid", "TEXT", "National ID card number (KYC for high-value orders)"),
            Column("city", "TEXT NOT NULL", "Default delivery city"),
            Column("area", "TEXT NOT NULL", "Thana / neighbourhood"),
            Column("address_line", "TEXT NOT NULL", "House, road and block"),
            Column("password_hash", "TEXT NOT NULL", "bcrypt hash of the account password"),
            Column("created_at", "TIMESTAMP NOT NULL", "Sign-up time (Asia/Dhaka)"),
        ),
    ),
    Table(
        "products",
        "Catalogue items with list prices in BDT",
        (
            Column("id", "INTEGER PRIMARY KEY", "Product id"),
            Column("sku", "TEXT NOT NULL UNIQUE", "Stock keeping unit"),
            Column("name", "TEXT NOT NULL", "Display name"),
            Column("category", "TEXT NOT NULL", "Top-level category"),
            Column("price_bdt", "NUMERIC(12,2) NOT NULL", "List price in Bangladeshi taka"),
            Column("stock", "INTEGER NOT NULL", "Units on hand in the Tejgaon warehouse"),
            Column("active", "BOOLEAN NOT NULL", "Listed on the storefront"),
        ),
    ),
    Table(
        "orders",
        "Customer orders; total_bdt includes delivery charge",
        (
            Column("id", "INTEGER PRIMARY KEY", "Order id"),
            Column("customer_id", "INTEGER NOT NULL", "Buyer"),
            Column(
                "status", "TEXT NOT NULL", "pending, paid, shipped, delivered, cancelled, refunded"
            ),
            Column("total_bdt", "NUMERIC(12,2) NOT NULL", "Order total in BDT incl. delivery"),
            Column("delivery_fee_bdt", "NUMERIC(12,2) NOT NULL", "Delivery charge in BDT"),
            Column("delivery_city", "TEXT NOT NULL", "City the parcel ships to"),
            Column("created_at", "TIMESTAMP NOT NULL", "Checkout time (Asia/Dhaka)"),
        ),
        ("FOREIGN KEY (customer_id) REFERENCES customers (id)",),
    ),
    Table(
        "order_items",
        "Line items of each order",
        (
            Column("id", "INTEGER PRIMARY KEY", "Line id"),
            Column("order_id", "INTEGER NOT NULL", "Parent order"),
            Column("product_id", "INTEGER NOT NULL", "Product sold"),
            Column("quantity", "INTEGER NOT NULL", "Units"),
            Column("unit_price_bdt", "NUMERIC(12,2) NOT NULL", "Price per unit at checkout"),
        ),
        (
            "FOREIGN KEY (order_id) REFERENCES orders (id)",
            "FOREIGN KEY (product_id) REFERENCES products (id)",
        ),
    ),
    Table(
        "payments",
        "Payment attempts per order (bKash, Nagad, card, cash on delivery)",
        (
            Column("id", "INTEGER PRIMARY KEY", "Payment id"),
            Column("order_id", "INTEGER NOT NULL", "Order being paid"),
            Column("method", "TEXT NOT NULL", "bkash, nagad, card or cod"),
            Column("amount_bdt", "NUMERIC(12,2) NOT NULL", "Amount in BDT"),
            Column("status", "TEXT NOT NULL", "success, failed or refunded"),
            Column("trx_id", "TEXT", "Gateway transaction id"),
            Column("payer_phone", "TEXT", "Wallet number for bKash / Nagad payments"),
            Column("paid_at", "TIMESTAMP", "Settlement time"),
        ),
        ("FOREIGN KEY (order_id) REFERENCES orders (id)",),
    ),
    Table(
        "staff_payroll",
        "HR data; blocked by the default policy",
        (
            Column("id", "INTEGER PRIMARY KEY", "Row id"),
            Column("staff_name", "TEXT NOT NULL", "Employee"),
            Column("salary_bdt", "NUMERIC(12,2) NOT NULL", "Monthly gross salary"),
        ),
    ),
)

INDEXES = (
    "CREATE INDEX idx_orders_customer ON orders (customer_id)",
    "CREATE INDEX idx_orders_created ON orders (created_at)",
    "CREATE INDEX idx_items_order ON order_items (order_id)",
    "CREATE INDEX idx_payments_order ON payments (order_id)",
)

FIRST_NAMES = (
    "Rahim Karim Tanvir Nusrat Farhana Sadia Arif Imran Mehedi Sumaiya Rafiq Shakil Tahmina "
    "Jannatul Anika Fahim Nadia Riyad Sabbir Mahmuda Ayesha Rakib Shirin Ashik Mim Tasnim"
).split()
LAST_NAMES = (
    "Hossain Rahman Islam Ahmed Chowdhury Khan Uddin Akter Begum Sarker Talukder Miah Haque "
    "Siddiqui Karim Bhuiyan Mollah Sheikh"
).split()
CITIES = {
    "Dhaka": ["Dhanmondi", "Gulshan", "Mirpur", "Uttara", "Banani", "Mohammadpur", "Bashundhara"],
    "Chattogram": ["Agrabad", "Nasirabad", "Halishahar", "Panchlaish"],
    "Sylhet": ["Zindabazar", "Amberkhana", "Shahjalal Upashahar"],
    "Khulna": ["Sonadanga", "Khalishpur"],
    "Rajshahi": ["Shaheb Bazar", "Uposhohor"],
    "Gazipur": ["Tongi", "Joydebpur"],
    "Narayanganj": ["Chashara", "Fatullah"],
}
CITY_WEIGHTS = (45, 18, 8, 7, 6, 9, 7)
CATALOGUE = {
    "Electronics": [
        ("32-inch Smart LED TV", 21500),
        ("Bluetooth Earbuds", 1850),
        ("Power Bank 20000mAh", 2200),
        ("Android Phone 128GB", 18999),
        ("Wi-Fi Router AC1200", 3450),
        ("Rechargeable Fan", 4290),
        ("IPS Monitor 24-inch", 13800),
        ("Electric Kettle 1.8L", 1650),
    ],
    "Fashion": [
        ("Cotton Panjabi", 1890),
        ("Jamdani Saree", 7800),
        ("Three-Piece Salwar Kameez", 2650),
        ("Leather Sandals", 1450),
        ("Lungi Check Pattern", 520),
        ("Winter Shawl", 1250),
        ("Denim Jeans", 1690),
        ("Hijab Georgette", 390),
    ],
    "Grocery": [
        ("Miniket Rice 25kg", 1880),
        ("Soybean Oil 5L", 845),
        ("Red Lentils 1kg", 135),
        ("Sugar 1kg", 128),
        ("Black Tea 400g", 245),
        ("Chinigura Rice 5kg", 690),
        ("Mustard Oil 1L", 290),
        ("Date Palm Molasses 1kg", 420),
    ],
    "Home & Kitchen": [
        ("Non-stick Frying Pan", 1350),
        ("Rice Cooker 1.8L", 3290),
        ("Bedsheet Set King", 2150),
        ("Prayer Mat", 650),
        ("Steel Water Bottle", 480),
        ("Blender 3-Jar", 4890),
    ],
    "Books": [
        ("Bangla Novel Collection", 950),
        ("HSC Physics Guide", 420),
        ("Children's Rhymes", 280),
        ("Python Programming (Bangla)", 680),
    ],
    "Beauty": [
        ("Herbal Face Wash", 340),
        ("Coconut Hair Oil 500ml", 275),
        ("Sunscreen SPF50", 890),
        ("Attar Gift Box", 1500),
    ],
}
PAYMENT_METHODS = ("bkash", "nagad", "card", "cod")
PAYMENT_WEIGHTS = (45, 20, 15, 20)
ORDER_STATUSES = ("delivered", "shipped", "paid", "pending", "cancelled", "refunded")
STATUS_WEIGHTS = (55, 12, 10, 8, 10, 5)
START = datetime(2025, 11, 1, 9, 0, 0)


def _phone(rng: random.Random) -> str:
    return f"+8801{rng.choice('3456789')}{rng.randrange(10**8):08d}"


def _money(value: float) -> Decimal:
    return Decimal(str(round(value, 2)))


def generate(seed: int = 42, customers: int = 300, orders: int = 2000) -> dict[str, list[tuple]]:
    """Build every row in memory. Same seed, same data."""
    rng = random.Random(seed)
    data: dict[str, list[tuple]] = {t.name: [] for t in SCHEMA}

    cities = list(CITIES)
    for cid in range(1, customers + 1):
        first, last = rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)
        city = rng.choices(cities, CITY_WEIGHTS)[0]
        area = rng.choice(CITIES[city])
        domain = rng.choice(("gmail.com", "gmail.com", "yahoo.com", "outlook.com"))
        email = f"{first.lower()}.{last.lower()}{cid}@{domain}"
        nid = "".join(rng.choice("0123456789") for _ in range(rng.choice((10, 17))))
        address = f"House {rng.randint(1, 120)}, Road {rng.randint(1, 30)}, {area}"
        pw = "$2b$12$" + hashlib.sha256(f"pw-{cid}".encode()).hexdigest()[:53]
        created = START - timedelta(days=rng.randint(0, 400), minutes=rng.randint(0, 1440))
        data["customers"].append(
            (
                cid,
                f"{first} {last}",
                email,
                _phone(rng),
                nid,
                city,
                area,
                address,
                pw,
                created.strftime("%Y-%m-%d %H:%M:%S"),
            )
        )

    product_rows = []
    pid = 0
    for category, items in CATALOGUE.items():
        for name, price in items:
            pid += 1
            sku = f"{category[:3].upper()}-{pid:04d}"
            product_rows.append(
                (pid, sku, name, category, _money(price), rng.randint(0, 400), rng.random() > 0.05)
            )
    data["products"] = product_rows

    item_id = 0
    payment_id = 0
    for oid in range(1, orders + 1):
        customer = data["customers"][rng.randrange(customers)]
        created = START + timedelta(minutes=rng.randint(0, 358 * 24 * 60))
        status = rng.choices(ORDER_STATUSES, STATUS_WEIGHTS)[0]
        city = customer[5] if rng.random() > 0.1 else rng.choices(cities, CITY_WEIGHTS)[0]
        fee = 60 if city == "Dhaka" else 120
        subtotal = 0.0
        for product in rng.sample(product_rows, rng.choice((1, 1, 2, 2, 3, 4))):
            item_id += 1
            qty = (
                rng.choice((1, 1, 1, 2, 2, 3, 5))
                if product[3] == "Grocery"
                else rng.choice((1, 1, 2))
            )
            price = float(product[4])
            if rng.random() < 0.2:
                price *= 0.9  # campaign discount
            subtotal += qty * round(price, 2)
            data["order_items"].append((item_id, oid, product[0], qty, _money(price)))
        total = _money(subtotal + fee)
        data["orders"].append(
            (
                oid,
                customer[0],
                status,
                total,
                _money(fee),
                city,
                created.strftime("%Y-%m-%d %H:%M:%S"),
            )
        )

        if status == "pending":
            continue
        method = rng.choices(PAYMENT_METHODS, PAYMENT_WEIGHTS)[0]
        if method in ("bkash", "nagad") and rng.random() < 0.12:
            payment_id += 1
            data["payments"].append(
                (payment_id, oid, method, total, "failed", None, customer[3], None)
            )
        payment_id += 1
        pay_status = {"refunded": "refunded", "cancelled": "failed"}.get(status, "success")
        prefix = {"bkash": "BK", "nagad": "NG", "card": "CD", "cod": "CO"}[method]
        trx = prefix + "".join(rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8))
        paid = created + timedelta(minutes=rng.randint(1, 90 if method != "cod" else 4000))
        data["payments"].append(
            (
                payment_id,
                oid,
                method,
                total,
                pay_status,
                trx if pay_status != "failed" else None,
                customer[3] if method in ("bkash", "nagad") else None,
                paid.strftime("%Y-%m-%d %H:%M:%S") if pay_status != "failed" else None,
            )
        )

    data["staff_payroll"] = [
        (1, "Warehouse Supervisor", _money(42000)),
        (2, "Customer Care Executive", _money(28000)),
        (3, "Delivery Rider", _money(18500)),
    ]
    return data


def ddl(table: Table, *, with_comments: bool) -> str:
    """CREATE TABLE text. SQLite keeps ``-- comments`` in sqlite_master for describe_table."""
    head = f"CREATE TABLE {table.name} (" + (f" -- {table.comment}" if with_comments else "")
    parts = [f"{c.name} {c.type}" for c in table.columns] + list(table.constraints)
    lines = [head]
    for index, (part, col) in enumerate(
        zip(parts, list(table.columns) + [None] * len(table.constraints), strict=True)
    ):
        comma = "," if index < len(parts) - 1 else ""
        comment = f" -- {col.comment}" if with_comments and col is not None else ""
        lines.append(f"    {part}{comma}{comment}")
    lines.append(")")
    return "\n".join(lines)


def seed_sqlite(path: Path, *, seed: int = 42, force: bool = False) -> dict[str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not force:
            raise FileExistsError(f"{path} exists; pass force=True (--force) to rebuild it")
        path.unlink()
    data = generate(seed)
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        for table in SCHEMA:
            conn.execute(ddl(table, with_comments=True))
        for statement in INDEXES:
            conn.execute(statement)
        for table in SCHEMA:
            rows = [tuple(_sqlite_value(v) for v in row) for row in data[table.name]]
            marks = ", ".join("?" for _ in table.columns)
            conn.executemany(f"INSERT INTO {table.name} VALUES ({marks})", rows)
        conn.commit()
    finally:
        conn.close()
    return {name: len(rows) for name, rows in data.items()}


def _sqlite_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, bool):
        return int(value)
    return value


def seed_postgres(
    url: str, *, seed: int = 42, readonly_role: str | None = "analyst_ro"
) -> dict[str, int]:
    import psycopg
    from psycopg import sql as pgsql

    data = generate(seed)
    with psycopg.connect(url, autocommit=False) as conn:
        with conn.cursor() as cur:
            for table in reversed(SCHEMA):
                cur.execute(
                    pgsql.SQL("DROP TABLE IF EXISTS {} CASCADE").format(
                        pgsql.Identifier(table.name)
                    )
                )
            for table in SCHEMA:
                cur.execute(ddl(table, with_comments=False))  # type: ignore[arg-type]
                cur.execute(
                    pgsql.SQL("COMMENT ON TABLE {} IS {}").format(
                        pgsql.Identifier(table.name), pgsql.Literal(table.comment)
                    )
                )
                for col in table.columns:
                    cur.execute(
                        pgsql.SQL("COMMENT ON COLUMN {}.{} IS {}").format(
                            pgsql.Identifier(table.name),
                            pgsql.Identifier(col.name),
                            pgsql.Literal(col.comment),
                        )
                    )
            for statement in INDEXES:
                cur.execute(statement)  # type: ignore[arg-type]
            for table in SCHEMA:
                marks = pgsql.SQL(", ").join(pgsql.Placeholder() for _ in table.columns)
                cur.executemany(
                    pgsql.SQL("INSERT INTO {} VALUES ({})").format(
                        pgsql.Identifier(table.name), marks
                    ),
                    data[table.name],
                )
            if readonly_role:
                cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (readonly_role,))
                if cur.fetchone():
                    role = pgsql.Identifier(readonly_role)
                    cur.execute(pgsql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(role))
                    cur.execute(
                        pgsql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA public TO {}").format(role)
                    )
                    # Defence in depth: the policy blocks payroll, and so does the database.
                    cur.execute(pgsql.SQL("REVOKE ALL ON staff_payroll FROM {}").format(role))
            cur.execute("ANALYZE")
        conn.commit()
    return {name: len(rows) for name, rows in data.items()}
