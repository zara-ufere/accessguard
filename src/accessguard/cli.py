"""Command line: accessguard serve | seed | scan | verify-audit | init-db."""
import argparse
import sys

from sqlalchemy.orm import Session

from . import audit, seed as seed_module, sod
from .config import database_url
from .db import init_db, make_engine


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="accessguard", description="Access governance service")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="run the API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    sub.add_parser("init-db", help="create tables if missing")
    sub.add_parser("seed", help="fill an empty database with demo data")
    sub.add_parser("scan", help="run a full separation of duties scan")
    sub.add_parser("verify-audit", help="check the audit chain (exit 1 if it was altered)")
    args = parser.parse_args(argv)

    if args.command == "serve":
        import uvicorn
        uvicorn.run("accessguard.api:app_factory", factory=True, host=args.host, port=args.port)
        return 0

    engine = make_engine(database_url())
    init_db(engine)
    with Session(engine) as session:
        if args.command == "init-db":
            print("Database ready.")
        elif args.command == "seed":
            if seed_module.seed(session):
                print("Demo data loaded.")
            else:
                print("Database already has users; nothing changed.")
        elif args.command == "scan":
            result = sod.scan(session, "cli")
            session.commit()
            print(f"Scan complete: {result.created} new, {result.refreshed} still open, {result.closed} closed.")
        elif args.command == "verify-audit":
            result = audit.verify(session)
            if result.ok:
                print(f"Audit chain intact: {result.checked} entries. Head hash {result.head_hash}")
            else:
                print(f"AUDIT CHAIN BROKEN at entry {result.first_bad_seq}: {result.problem}", file=sys.stderr)
                return 1
    return 0
