import argparse
from datetime import datetime, timedelta

from api import LoginSession, Scan, SessionLocal


def purge_expired_data(db, retention_days, now=None):
    if not 1 <= retention_days <= 3650:
        raise ValueError("retention_days must be between 1 and 3650.")

    now = now or datetime.utcnow()
    cutoff = now - timedelta(days=retention_days)
    removed_scans = (
        db.query(Scan)
        .filter(
            Scan.status.in_(("completed", "failed")),
            Scan.created_at < cutoff,
        )
        .delete(synchronize_session=False)
    )
    removed_sessions = (
        db.query(LoginSession)
        .filter(LoginSession.expires_at < now)
        .delete(synchronize_session=False)
    )
    db.commit()
    return removed_scans, removed_sessions


def main():
    parser = argparse.ArgumentParser(
        description="Run scheduled AI Risk Scanner data-retention maintenance."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    purge = subparsers.add_parser(
        "purge-expired", help="delete completed/failed scans past the configured retention"
    )
    purge.add_argument(
        "--retention-days",
        type=int,
        required=True,
        help="retention period approved for the deployment (1-3650 days)",
    )
    args = parser.parse_args()

    db = SessionLocal()
    try:
        removed_scans, removed_sessions = purge_expired_data(
            db, args.retention_days
        )
    finally:
        db.close()
    print(
        "Removed %d expired scan records and %d expired login sessions."
        % (removed_scans, removed_sessions)
    )


if __name__ == "__main__":
    main()
