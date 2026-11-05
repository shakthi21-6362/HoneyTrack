"""Database initialization module for HoneyTrack supporting SQLite & PostgreSQL/TimescaleDB."""

import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from config.settings import DATABASE_URL, IS_POSTGRES, DATABASE_PATH

logger = logging.getLogger(__name__)

# Configure engine arguments based on dialect
engine_kwargs = {}
if not IS_POSTGRES:
    # SQLite-specific concurrency settings
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    # PostgreSQL connection pooling optimizations
    engine_kwargs["pool_size"] = 10
    engine_kwargs["max_overflow"] = 20
    engine_kwargs["pool_pre_ping"] = True

try:
    engine = create_engine(
        DATABASE_URL,
        **engine_kwargs
    )
except Exception as e:
    if IS_POSTGRES:
        logger.warning(f"[DB] PostgreSQL driver/engine error ({e}). Falling back to SQLite.")
        DATABASE_URL = f"sqlite:///{DATABASE_PATH}"
        IS_POSTGRES = False
        engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    else:
        raise

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def init_db():
    """Initialize the database and create all tables and TimescaleDB hypertable if available."""
    from database.models import AttackEvent, BlockedIP  # noqa: F401 — ensure model is registered
    from database.user_model import User  # noqa: F401
    Base.metadata.create_all(bind=engine)

    # Dialect-specific migrations and optimizations
    if not IS_POSTGRES:
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
            logger.warning(f"[DB] SQLite migration notice: {e}")
    else:
        # PostgreSQL / TimescaleDB automatic hypertable & index setup
        try:
            with engine.connect() as conn:
                # Check if TimescaleDB extension is present or can be enabled
                try:
                    conn.exec_driver_sql("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")
                    conn.commit()
                    logger.info("[DB] TimescaleDB extension enabled.")
                except Exception as ext_err:
                    conn.rollback()
                    logger.info(f"[DB] TimescaleDB extension notice (running standard PostgreSQL): {ext_err}")

                # Check if attack_events is already a hypertable
                try:
                    is_hyper = conn.exec_driver_sql(
                        "SELECT count(*) FROM timescaledb_information.hypertables WHERE hypertable_name = 'attack_events';"
                    ).scalar()
                    if is_hyper == 0:
                        # Convert attack_events to a high-performance time-series hypertable partitioned by timestamp
                        # Drop single-column primary key constraint if needed or create hypertable
                        conn.exec_driver_sql(
                            "SELECT create_hypertable('attack_events', 'timestamp', migrate_data => true, if_not_exists => true);"
                        )
                        conn.commit()
                        logger.info("[DB] [+] Successfully converted 'attack_events' into TimescaleDB hypertable!")
                except Exception as ht_err:
                    conn.rollback()
                    logger.debug(f"[DB] Hypertable initialization notice: {ht_err}")

                # Ensure high-throughput indexes on PostgreSQL
                try:
                    conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_attack_events_ts_srv ON attack_events (timestamp DESC, service);")
                    conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_attack_events_ip ON attack_events (source_ip);")
                    conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_attack_events_risk ON attack_events (risk_score DESC);")
                    conn.commit()
                except Exception as idx_err:
                    conn.rollback()
                    logger.debug(f"[DB] Index creation notice: {idx_err}")

        except Exception as e:
            logger.warning(f"[DB] PostgreSQL initialization notice: {e}")

    logger.info(f"[DB] Database initialized ({'PostgreSQL/TimescaleDB' if IS_POSTGRES else 'SQLite'}).")


def get_db():
    """Yield a database session (context-manager friendly)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()