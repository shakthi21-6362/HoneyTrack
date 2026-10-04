"""Database initialization module for HoneyTrack."""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from config.settings import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def init_db():
    """Initialize the database and create all tables."""
    from database.models import AttackEvent, BlockedIP  # noqa: F401 — ensure model is registered
    from database.user_model import User  # noqa: F401
    Base.metadata.create_all(bind=engine)

    # Lightweight SQLite migration for dynamic columns
    try:
        with engine.connect() as conn:
            cursor = conn.exec_driver_sql("PRAGMA table_info(attack_events)")
            columns = [row[1] for row in cursor.fetchall()]
            if "is_tor" not in columns:
                conn.exec_driver_sql("ALTER TABLE attack_events ADD COLUMN is_tor BOOLEAN DEFAULT 0")
            if "is_demo" not in columns:
                conn.exec_driver_sql("ALTER TABLE attack_events ADD COLUMN is_demo BOOLEAN DEFAULT 0")
                # Backfill all historical events as demo data
                conn.exec_driver_sql("UPDATE attack_events SET is_demo = 1")
            if "origin_node" not in columns:
                conn.exec_driver_sql("ALTER TABLE attack_events ADD COLUMN origin_node VARCHAR(64) DEFAULT 'local'")
            conn.commit()

            cursor_b = conn.exec_driver_sql("PRAGMA table_info(blocked_ips)")
            columns_b = [row[1] for row in cursor_b.fetchall()]
            if "origin_node" not in columns_b:
                conn.exec_driver_sql("ALTER TABLE blocked_ips ADD COLUMN origin_node VARCHAR(64) DEFAULT 'local'")
                conn.commit()
    except Exception as e:
        print(f"[DB] Migration notice: {e}")

    print("[DB] Database initialized.")


def get_db():
    """Yield a database session (context-manager friendly)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()