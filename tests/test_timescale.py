"""Tests for PostgreSQL / TimescaleDB integration and dialect compatibility."""

import os
import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from config import settings


def test_postgres_settings_configuration():
    """Verify DATABASE_URL assembly and IS_POSTGRES flag from environment variables."""
    # Test SQLite fallback
    with patch.dict(os.environ, {"ENV_FILE": "nonexistent.env"}, clear=True):
        import importlib
        importlib.reload(settings)
        assert not settings.IS_POSTGRES
        assert settings.DATABASE_URL.startswith("sqlite:///")

    # Test explicit POSTGRES_* env vars
    test_env = {
        "ENV_FILE": "nonexistent.env",
        "POSTGRES_HOST": "localhost",
        "POSTGRES_PORT": "5432",
        "POSTGRES_USER": "testuser",
        "POSTGRES_PASSWORD": "testpass2026",
        "POSTGRES_DB": "honeytrack_test"
    }
    with patch.dict(os.environ, test_env, clear=True):
        import importlib
        importlib.reload(settings)
        assert settings.IS_POSTGRES
        assert settings.DATABASE_URL == "postgresql+psycopg://testuser:testpass2026@localhost:5432/honeytrack_test"

    # Reload back to normal environment
    import importlib
    importlib.reload(settings)


def test_sqlite_and_postgres_init_db_paths():
    """Verify init_db executes cleanly without exceptions on SQLite and handles Postgres branches."""
    from database import database
    # Test on active SQLite database
    database.init_db()

    # Test with mocked engine for PostgreSQL branch
    mock_engine = MagicMock()
    mock_conn = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn

    # Simulate TimescaleDB count check returning 0
    mock_conn.exec_driver_sql.return_value.scalar.return_value = 0

    with patch("database.database.engine", mock_engine), \
         patch("database.database.IS_POSTGRES", True):
        database.init_db()

        # Check that extension and hypertable commands were executed
        sql_calls = [call[0][0] for call in mock_conn.exec_driver_sql.call_args_list]
        assert any("CREATE EXTENSION IF NOT EXISTS timescaledb" in str(c) for c in sql_calls)
        assert any("create_hypertable" in str(c) for c in sql_calls)
        assert any("idx_attack_events_ts_srv" in str(c) for c in sql_calls)
