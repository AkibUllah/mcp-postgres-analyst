"""Seed the demo shop database (SQLite by default, PostgreSQL with --database-url).

python scripts/seed_demo.py                                   # -> data/demo.db
python scripts/seed_demo.py --force                           # rebuild it
python scripts/seed_demo.py --database-url postgresql://shop:shop@localhost:5432/shop
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pg_analyst.db import sqlite_path_from_url
from pg_analyst.demo import seed_postgres, seed_sqlite


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--database-url", default="sqlite:///data/demo.db")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--force", action="store_true", help="overwrite an existing SQLite file")
    parser.add_argument(
        "--readonly-role",
        default="analyst_ro",
        help="PostgreSQL role to grant SELECT to (if it exists)",
    )
    args = parser.parse_args(argv)

    if args.database_url.startswith("sqlite:"):
        path = sqlite_path_from_url(args.database_url)
        if path.exists() and not args.force:
            print(f"{path} already exists (use --force to rebuild)")
            return 0
        counts = seed_sqlite(Path(path), seed=args.seed, force=args.force)
        target = str(path)
    else:
        counts = seed_postgres(args.database_url, seed=args.seed, readonly_role=args.readonly_role)
        target = args.database_url.rsplit("@", 1)[-1]
    summary = ", ".join(f"{name}={count}" for name, count in counts.items())
    print(f"seeded {target}: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
