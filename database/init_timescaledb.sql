-- =============================================================================
-- HoneyTrack TimescaleDB / PostgreSQL Time-Series Initializer
-- Enables TimescaleDB extension and hypertable optimization for attack_events
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Note: HoneyTrack SQLAlchemy models create tables upon boot.
-- If the table already exists, convert to hypertable partitioned on 'timestamp'.
DO $$
BEGIN
    IF EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'attack_events'
    ) THEN
        IF NOT EXISTS (
            SELECT FROM timescaledb_information.hypertables 
            WHERE hypertable_name = 'attack_events'
        ) THEN
            PERFORM create_hypertable('attack_events', 'timestamp', migrate_data => true, if_not_exists => true);
        END IF;
    END IF;
END $$;
