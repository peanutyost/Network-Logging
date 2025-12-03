"""PostgreSQL database implementation."""
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor, execute_values
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import json
import logging

from .base import DatabaseBase
from config import config

logger = logging.getLogger(__name__)


class PostgreSQLDatabase(DatabaseBase):
    """PostgreSQL implementation of database operations."""
    
    def __init__(self):
        """Initialize PostgreSQL connection pool."""
        self.connection_pool = None
        self.db_config = config.database
    
    def connect(self) -> None:
        """Establish database connection pool."""
        try:
            self.connection_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=10,
                host=self.db_config.host,
                port=self.db_config.port,
                database=self.db_config.name,
                user=self.db_config.user,
                password=self.db_config.password,
                options='-c timezone=UTC'
            )
            # Set timezone to UTC for all connections
            conn = self.connection_pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute("SET timezone = 'UTC'")
                    conn.commit()
            finally:
                self.connection_pool.putconn(conn)
            logger.info("Connected to PostgreSQL database (UTC timezone)")
        except Exception as e:
            logger.error(f"Error connecting to database: {e}")
            raise
    
    def disconnect(self) -> None:
        """Close database connection pool."""
        if self.connection_pool:
            self.connection_pool.closeall()
            logger.info("Disconnected from PostgreSQL database")
    
    def _get_connection(self):
        """Get connection from pool."""
        if not self.connection_pool:
            self.connect()
        conn = self.connection_pool.getconn()
        # Ensure timezone is UTC for this connection
        try:
            with conn.cursor() as cur:
                cur.execute("SET timezone = 'UTC'")
                conn.commit()
        except:
            pass  # If it fails, connection might already be set
        return conn
    
    def _return_connection(self, conn):
        """Return connection to pool."""
        self.connection_pool.putconn(conn)
    
    def create_tables(self) -> None:
        """Create all required database tables."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                # DNS Lookups table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dns_lookups (
                        id SERIAL PRIMARY KEY,
                        domain VARCHAR(255) NOT NULL,
                        query_type VARCHAR(10) NOT NULL,
                        resolved_ips JSONB NOT NULL,
                        query_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(domain, query_type)
                    )
                """)
                
                # Add first_seen column if it doesn't exist (for existing databases)
                cur.execute("""
                    DO $$ 
                    BEGIN 
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='dns_lookups' AND column_name='first_seen'
                        ) THEN
                            ALTER TABLE dns_lookups ADD COLUMN first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;
                        END IF;
                    END $$;
                """)
                
                # Create indexes
                cur.execute("CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_lookups(domain)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_dns_ips ON dns_lookups USING GIN(resolved_ips)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_lookups(query_timestamp)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_dns_first_seen ON dns_lookups(first_seen)")
                
                # Traffic Flows table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS traffic_flows (
                        id SERIAL PRIMARY KEY,
                        source_ip INET NOT NULL,
                        destination_ip INET NOT NULL,
                        destination_port INTEGER NOT NULL,
                        protocol VARCHAR(10) NOT NULL,
                        domain VARCHAR(255),
                        bytes_sent BIGINT NOT NULL DEFAULT 0,
                        bytes_received BIGINT NOT NULL DEFAULT 0,
                        packet_count INTEGER NOT NULL DEFAULT 0,
                        first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        last_update TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        is_orphaned BOOLEAN NOT NULL DEFAULT FALSE,
                        is_abnormal BOOLEAN NOT NULL DEFAULT FALSE,
                        UNIQUE(source_ip, destination_ip, destination_port, protocol)
                    )
                """)
                
                # Add is_abnormal column if it doesn't exist (migration)
                cur.execute("""
                    SELECT COUNT(*) FROM information_schema.columns 
                    WHERE table_name='traffic_flows' AND column_name='is_abnormal'
                """)
                if cur.fetchone()[0] == 0:
                    cur.execute("ALTER TABLE traffic_flows ADD COLUMN is_abnormal BOOLEAN NOT NULL DEFAULT FALSE")
                
                # Create indexes
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flow_source ON traffic_flows(source_ip)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flow_dest ON traffic_flows(destination_ip)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flow_dest_port ON traffic_flows(destination_port)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flow_domain ON traffic_flows(domain)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flow_orphaned ON traffic_flows(is_orphaned)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flow_abnormal ON traffic_flows(is_abnormal)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flow_timestamp ON traffic_flows(last_update)")
                
                # WHOIS Data table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS whois_data (
                        id SERIAL PRIMARY KEY,
                        domain VARCHAR(255) NOT NULL UNIQUE,
                        whois_data JSONB NOT NULL,
                        whois_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                cur.execute("CREATE INDEX IF NOT EXISTS idx_whois_domain ON whois_data(domain)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_whois_updated ON whois_data(whois_updated_at)")

                # DNS Events table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dns_events (
                        id SERIAL PRIMARY KEY,
                        event_type VARCHAR(10) NOT NULL, -- 'query' or 'response'
                        domain VARCHAR(255) NOT NULL,
                        query_type VARCHAR(10) NOT NULL,
                        source_ip INET NOT NULL,
                        destination_ip INET NOT NULL,
                        resolved_ips JSONB,
                        event_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_dnsevents_time ON dns_events(event_timestamp)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_dnsevents_domain ON dns_events(domain)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_dnsevents_src ON dns_events(source_ip)")
                
                # Users table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(255) NOT NULL UNIQUE,
                        email VARCHAR(255) NOT NULL UNIQUE,
                        hashed_password TEXT NOT NULL,
                        is_admin BOOLEAN NOT NULL DEFAULT FALSE,
                        is_active BOOLEAN NOT NULL DEFAULT TRUE,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
                
                # Threat Feeds table (metadata about threat intelligence feeds)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS threat_feeds (
                        id SERIAL PRIMARY KEY,
                        feed_name VARCHAR(255) NOT NULL UNIQUE,
                        source_url TEXT NOT NULL,
                        enabled BOOLEAN NOT NULL DEFAULT TRUE,
                        last_update TIMESTAMP,
                        indicator_count INTEGER NOT NULL DEFAULT 0,
                        last_error TEXT,
                        homepage TEXT,
                        config JSONB,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                # Migrate columns if they don't exist (for existing databases)
                cur.execute("""
                    DO $$ 
                    BEGIN 
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_feeds' AND column_name='feed_name'
                        ) THEN
                            ALTER TABLE threat_feeds ADD COLUMN feed_name VARCHAR(255) NOT NULL DEFAULT 'Unknown';
                            CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_feeds_name_unique ON threat_feeds(feed_name);
                            ALTER TABLE threat_feeds ALTER COLUMN feed_name DROP DEFAULT;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_feeds' AND column_name='source_url'
                        ) THEN
                            ALTER TABLE threat_feeds ADD COLUMN source_url TEXT NOT NULL DEFAULT '';
                            ALTER TABLE threat_feeds ALTER COLUMN source_url DROP DEFAULT;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_feeds' AND column_name='enabled'
                        ) THEN
                            ALTER TABLE threat_feeds ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_feeds' AND column_name='last_update'
                        ) THEN
                            ALTER TABLE threat_feeds ADD COLUMN last_update TIMESTAMP;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_feeds' AND column_name='indicator_count'
                        ) THEN
                            ALTER TABLE threat_feeds ADD COLUMN indicator_count INTEGER NOT NULL DEFAULT 0;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_feeds' AND column_name='last_error'
                        ) THEN
                            ALTER TABLE threat_feeds ADD COLUMN last_error TEXT;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_feeds' AND column_name='created_at'
                        ) THEN
                            ALTER TABLE threat_feeds ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_feeds' AND column_name='updated_at'
                        ) THEN
                            ALTER TABLE threat_feeds ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_feeds' AND column_name='homepage'
                        ) THEN
                            ALTER TABLE threat_feeds ADD COLUMN homepage TEXT;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_feeds' AND column_name='config'
                        ) THEN
                            ALTER TABLE threat_feeds ADD COLUMN config JSONB;
                        END IF;
                    END $$;
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_feeds_name ON threat_feeds(feed_name)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_feeds_enabled ON threat_feeds(enabled)")
                
                # Threat Indicators table (actual domains and IPs from feeds)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS threat_indicators (
                        id SERIAL PRIMARY KEY,
                        feed_name VARCHAR(255) NOT NULL,
                        indicator_type VARCHAR(10) NOT NULL, -- 'domain' or 'ip'
                        domain VARCHAR(255),
                        ip INET,
                        first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                # Migrate columns if they don't exist (for existing databases)
                cur.execute("""
                    DO $$ 
                    BEGIN 
                        -- Add feed_name if missing
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_indicators' AND column_name='feed_name'
                        ) THEN
                            ALTER TABLE threat_indicators ADD COLUMN feed_name VARCHAR(255) NOT NULL DEFAULT 'Unknown';
                            ALTER TABLE threat_indicators ALTER COLUMN feed_name DROP DEFAULT;
                        END IF;
                        
                        -- Add indicator_type if missing
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_indicators' AND column_name='indicator_type'
                        ) THEN
                            ALTER TABLE threat_indicators ADD COLUMN indicator_type VARCHAR(10) NOT NULL DEFAULT 'domain';
                            ALTER TABLE threat_indicators ALTER COLUMN indicator_type DROP DEFAULT;
                        END IF;
                        
                        -- Add domain if missing
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_indicators' AND column_name='domain'
                        ) THEN
                            ALTER TABLE threat_indicators ADD COLUMN domain VARCHAR(255);
                        END IF;
                        
                        -- Add ip if missing
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_indicators' AND column_name='ip'
                        ) THEN
                            ALTER TABLE threat_indicators ADD COLUMN ip INET;
                        END IF;
                        
                        -- Add first_seen if missing
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_indicators' AND column_name='first_seen'
                        ) THEN
                            ALTER TABLE threat_indicators ADD COLUMN first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;
                        END IF;
                        
                        -- Add last_seen if missing
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_indicators' AND column_name='last_seen'
                        ) THEN
                            ALTER TABLE threat_indicators ADD COLUMN last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;
                        END IF;
                        
                        -- Remove old columns that are no longer used
                        IF EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_indicators' AND column_name='severity'
                        ) THEN
                            ALTER TABLE threat_indicators DROP COLUMN severity;
                        END IF;
                        
                        IF EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_indicators' AND column_name='source_ip'
                        ) THEN
                            ALTER TABLE threat_indicators DROP COLUMN source_ip;
                        END IF;
                        
                        IF EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_indicators' AND column_name='destination_ip'
                        ) THEN
                            ALTER TABLE threat_indicators DROP COLUMN destination_ip;
                        END IF;
                        
                        IF EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_indicators' AND column_name='description'
                        ) THEN
                            ALTER TABLE threat_indicators DROP COLUMN description;
                        END IF;
                        
                        IF EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_indicators' AND column_name='detected_at'
                        ) THEN
                            ALTER TABLE threat_indicators DROP COLUMN detected_at;
                        END IF;
                    END $$;
                """)
                # Drop old indexes that reference removed columns
                cur.execute("DROP INDEX IF EXISTS idx_threat_type")
                cur.execute("DROP INDEX IF EXISTS idx_threat_severity")
                cur.execute("DROP INDEX IF EXISTS idx_threat_detected")
                # Drop index if it exists (in case we need to recreate it)
                cur.execute("DROP INDEX IF EXISTS idx_threat_ind_unique")
                # Create unique index to ensure no duplicates per feed/type/indicator
                # Use COALESCE with explicit text casting for the index
                cur.execute("""
                    CREATE UNIQUE INDEX idx_threat_ind_unique 
                    ON threat_indicators (
                        feed_name, 
                        indicator_type, 
                        COALESCE(domain, ''), 
                        COALESCE(CAST(ip AS TEXT), '')
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_ind_feed ON threat_indicators(feed_name)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_ind_type ON threat_indicators(indicator_type)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_ind_domain ON threat_indicators(domain)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_ind_ip ON threat_indicators(ip)")
                
                # Threat Alerts table (alerts when matches are detected)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS threat_alerts (
                        id SERIAL PRIMARY KEY,
                        feed_name VARCHAR(255) NOT NULL,
                        indicator_type VARCHAR(10) NOT NULL, -- 'domain' or 'ip'
                        domain VARCHAR(255),
                        ip INET,
                        query_type VARCHAR(10) NOT NULL,
                        source_ip INET NOT NULL,
                        resolved BOOLEAN NOT NULL DEFAULT FALSE,
                        resolved_at TIMESTAMP,
                        resolved_by INTEGER,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                # Migrate columns if they don't exist (for existing databases)
                cur.execute("""
                    DO $$ 
                    BEGIN 
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_alerts' AND column_name='feed_name'
                        ) THEN
                            ALTER TABLE threat_alerts ADD COLUMN feed_name VARCHAR(255) NOT NULL DEFAULT 'Unknown';
                            ALTER TABLE threat_alerts ALTER COLUMN feed_name DROP DEFAULT;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_alerts' AND column_name='indicator_type'
                        ) THEN
                            ALTER TABLE threat_alerts ADD COLUMN indicator_type VARCHAR(10) NOT NULL DEFAULT 'domain';
                            ALTER TABLE threat_alerts ALTER COLUMN indicator_type DROP DEFAULT;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_alerts' AND column_name='domain'
                        ) THEN
                            ALTER TABLE threat_alerts ADD COLUMN domain VARCHAR(255);
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_alerts' AND column_name='ip'
                        ) THEN
                            ALTER TABLE threat_alerts ADD COLUMN ip INET;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_alerts' AND column_name='query_type'
                        ) THEN
                            ALTER TABLE threat_alerts ADD COLUMN query_type VARCHAR(10) NOT NULL DEFAULT 'A';
                            ALTER TABLE threat_alerts ALTER COLUMN query_type DROP DEFAULT;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_alerts' AND column_name='source_ip'
                        ) THEN
                            ALTER TABLE threat_alerts ADD COLUMN source_ip INET NOT NULL DEFAULT '0.0.0.0';
                            ALTER TABLE threat_alerts ALTER COLUMN source_ip DROP DEFAULT;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_alerts' AND column_name='resolved'
                        ) THEN
                            ALTER TABLE threat_alerts ADD COLUMN resolved BOOLEAN NOT NULL DEFAULT FALSE;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_alerts' AND column_name='resolved_at'
                        ) THEN
                            ALTER TABLE threat_alerts ADD COLUMN resolved_at TIMESTAMP;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_alerts' AND column_name='resolved_by'
                        ) THEN
                            ALTER TABLE threat_alerts ADD COLUMN resolved_by INTEGER;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_alerts' AND column_name='created_at'
                        ) THEN
                            ALTER TABLE threat_alerts ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;
                        END IF;
                    END $$;
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_alerts_feed ON threat_alerts(feed_name)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_alerts_resolved ON threat_alerts(resolved)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_alerts_created ON threat_alerts(created_at)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_alerts_domain ON threat_alerts(domain)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_alerts_ip ON threat_alerts(ip)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_alerts_src ON threat_alerts(source_ip)")
                
                # Threat Whitelist table (domains/IPs that should not trigger alerts)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS threat_whitelist (
                        id SERIAL PRIMARY KEY,
                        indicator_type VARCHAR(10) NOT NULL, -- 'domain' or 'ip'
                        domain VARCHAR(255),
                        ip INET,
                        reason TEXT,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        created_by INTEGER
                    )
                """)
                # Migrate columns if they don't exist
                cur.execute("""
                    DO $$ 
                    BEGIN 
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_whitelist' AND column_name='indicator_type'
                        ) THEN
                            ALTER TABLE threat_whitelist ADD COLUMN indicator_type VARCHAR(10) NOT NULL DEFAULT 'domain';
                            ALTER TABLE threat_whitelist ALTER COLUMN indicator_type DROP DEFAULT;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_whitelist' AND column_name='domain'
                        ) THEN
                            ALTER TABLE threat_whitelist ADD COLUMN domain VARCHAR(255);
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_whitelist' AND column_name='ip'
                        ) THEN
                            ALTER TABLE threat_whitelist ADD COLUMN ip INET;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_whitelist' AND column_name='reason'
                        ) THEN
                            ALTER TABLE threat_whitelist ADD COLUMN reason TEXT;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_whitelist' AND column_name='created_at'
                        ) THEN
                            ALTER TABLE threat_whitelist ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;
                        END IF;
                        
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name='threat_whitelist' AND column_name='created_by'
                        ) THEN
                            ALTER TABLE threat_whitelist ADD COLUMN created_by INTEGER;
                        END IF;
                    END $$;
                """)
                cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_whitelist_domain ON threat_whitelist(domain) WHERE domain IS NOT NULL")
                cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_whitelist_ip ON threat_whitelist(ip) WHERE ip IS NOT NULL")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_whitelist_type ON threat_whitelist(indicator_type)")
                
                # Settings table (application configuration)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS settings (
                        id SERIAL PRIMARY KEY,
                        key VARCHAR(255) NOT NULL UNIQUE,
                        value TEXT NOT NULL,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(key)")
                
                conn.commit()
                logger.info("Database tables created successfully")
        except Exception as e:
            conn.rollback()
            logger.error(f"Error creating tables: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    def insert_dns_lookup(
        self,
        domain: str,
        query_type: str,
        resolved_ips: List[str],
        timestamp: Optional[datetime] = None,
        first_seen: Optional[datetime] = None
    ) -> int:
        """Insert or update a DNS lookup entry."""
        if timestamp is None:
            timestamp = datetime.utcnow()
        if first_seen is None:
            first_seen = timestamp
        
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                # Check if domain already exists to preserve first_seen
                cur.execute("""
                    SELECT first_seen FROM dns_lookups
                    WHERE domain = %s AND query_type = %s
                """, (domain, query_type))
                
                existing = cur.fetchone()
                if existing:
                    first_seen = existing[0]  # Preserve original first_seen
                
                cur.execute("""
                    INSERT INTO dns_lookups (domain, query_type, resolved_ips, query_timestamp, first_seen, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (domain, query_type)
                    DO UPDATE SET
                        resolved_ips = EXCLUDED.resolved_ips,
                        last_seen = EXCLUDED.last_seen
                    RETURNING id
                """, (domain, query_type, json.dumps(resolved_ips), timestamp, first_seen, timestamp))
                
                result = cur.fetchone()
                conn.commit()
                return result[0] if result else 0
        except Exception as e:
            conn.rollback()
            logger.error(f"Error inserting DNS lookup: {e}")
            raise
        finally:
            self._return_connection(conn)

    def get_recent_dns_queries(self, limit: int = 100, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get recent DNS queries ordered by last_seen desc."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if since:
                    cur.execute(
                        """
                        SELECT * FROM dns_lookups
                        WHERE last_seen >= %s
                        ORDER BY last_seen DESC
                        LIMIT %s
                        """,
                        (since, limit),
                    )
                else:
                    cur.execute(
                        """
                        SELECT * FROM dns_lookups
                        ORDER BY last_seen DESC
                        LIMIT %s
                        """,
                        (limit,),
                    )
                rows = cur.fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error getting recent DNS queries: {e}")
            return []
        finally:
            self._return_connection(conn)

    def get_dns_lookup_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get DNS lookup information by domain."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT * FROM dns_lookups
                    WHERE domain = %s
                    ORDER BY last_seen DESC
                    LIMIT 1
                    """,
                    (domain,),
                )
                
                result = cur.fetchone()
                return dict(result) if result else None
        except Exception as e:
            logger.error(f"Error getting DNS lookup: {e}")
            return None
        finally:
            self._return_connection(conn)
    
    def get_domain_by_ip(self, ip: str, days: int = 7, before_timestamp: Optional[datetime] = None) -> Optional[str]:
        """Get domain name for an IP address if it was resolved in the last N days.
        
        If before_timestamp is provided, only returns DNS records that occurred before that time.
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                query = """
                    SELECT domain FROM dns_lookups
                    WHERE resolved_ips @> %s::jsonb
                    AND last_seen >= %s
                """
                params = [json.dumps([ip]), cutoff_date]
                
                if before_timestamp:
                    query += " AND first_seen <= %s"
                    params.append(before_timestamp)
                
                query += " ORDER BY first_seen DESC LIMIT 1"
                
                cur.execute(query, params)
                
                result = cur.fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.error(f"Error getting domain by IP: {e}")
            return None
        finally:
            self._return_connection(conn)
    
    def get_dns_lookups_by_ip(
        self,
        ip: str,
        limit: int = 1000,
        offset: int = 0,
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """Get all DNS lookups that resolved to a specific IP address with pagination."""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM dns_lookups
                    WHERE resolved_ips @> %s::jsonb
                    AND last_seen >= %s
                    ORDER BY last_seen DESC
                    LIMIT %s OFFSET %s
                """, (json.dumps([ip]), cutoff_date, limit, offset))
                
                results = cur.fetchall()
                return [dict(r) for r in results]
        except Exception as e:
            logger.error(f"Error getting DNS lookups by IP: {e}")
            return []
        finally:
            self._return_connection(conn)
    
    def get_dns_lookups_by_ip_count(
        self,
        ip: str,
        days: int = 30
    ) -> int:
        """Get total count of DNS lookups that resolved to a specific IP address."""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM dns_lookups
                    WHERE resolved_ips @> %s::jsonb
                    AND last_seen >= %s
                """, (json.dumps([ip]), cutoff_date))
                
                result = cur.fetchone()
                return result[0] if result else 0
        except Exception as e:
            logger.error(f"Error getting DNS lookups by IP count: {e}")
            return 0
        finally:
            self._return_connection(conn)
    
    def search_domains(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search for domains matching a query string."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM dns_lookups
                    WHERE domain ILIKE %s
                    ORDER BY last_seen DESC
                    LIMIT %s
                """, (f"%{query}%", limit))
                
                results = cur.fetchall()
                return [dict(r) for r in results]
        except Exception as e:
            logger.error(f"Error searching domains: {e}")
            return []
        finally:
            self._return_connection(conn)
    
    def upsert_traffic_flow(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        protocol: str,
        bytes_sent: int,
        bytes_received: int,
        packet_count: int,
        domain: Optional[str] = None,
        first_seen: Optional[datetime] = None,
        is_abnormal: bool = False
    ) -> int:
        """Insert or update a traffic flow entry.
        
        source_ip is RFC1918 client IP (or source IP for abnormal flows), destination_ip is public server IP.
        Domain is looked up from DNS records that occurred before first_seen.
        """
        # Look up domain from DNS records that occurred before the flow started
        # Skip domain lookup for abnormal flows
        if not domain and not is_abnormal:
            domain = self.get_domain_by_ip(destination_ip, config.orphaned_ip_days, before_timestamp=first_seen)
        
        is_orphaned = domain is None
        
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                if first_seen:
                    cur.execute("""
                        INSERT INTO traffic_flows (
                            source_ip, destination_ip, destination_port, protocol,
                            domain, bytes_sent, bytes_received, packet_count, is_orphaned, is_abnormal, first_seen
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (source_ip, destination_ip, destination_port, protocol)
                        DO UPDATE SET
                            bytes_sent = traffic_flows.bytes_sent + EXCLUDED.bytes_sent,
                            bytes_received = traffic_flows.bytes_received + EXCLUDED.bytes_received,
                            packet_count = traffic_flows.packet_count + EXCLUDED.packet_count,
                            last_update = CURRENT_TIMESTAMP,
                            domain = COALESCE(EXCLUDED.domain, traffic_flows.domain),
                            is_orphaned = EXCLUDED.is_orphaned,
                            is_abnormal = EXCLUDED.is_abnormal,
                            first_seen = LEAST(EXCLUDED.first_seen, traffic_flows.first_seen)
                        RETURNING id
                    """, (
                        source_ip, destination_ip, destination_port, protocol,
                        domain, bytes_sent, bytes_received, packet_count, is_orphaned, is_abnormal, first_seen
                    ))
                else:
                    cur.execute("""
                        INSERT INTO traffic_flows (
                            source_ip, destination_ip, destination_port, protocol,
                            domain, bytes_sent, bytes_received, packet_count, is_orphaned, is_abnormal
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (source_ip, destination_ip, destination_port, protocol)
                        DO UPDATE SET
                            bytes_sent = traffic_flows.bytes_sent + EXCLUDED.bytes_sent,
                            bytes_received = traffic_flows.bytes_received + EXCLUDED.bytes_received,
                            packet_count = traffic_flows.packet_count + EXCLUDED.packet_count,
                            last_update = CURRENT_TIMESTAMP,
                            domain = COALESCE(EXCLUDED.domain, traffic_flows.domain),
                            is_orphaned = EXCLUDED.is_orphaned,
                            is_abnormal = EXCLUDED.is_abnormal
                        RETURNING id
                    """, (
                        source_ip, destination_ip, destination_port, protocol,
                        domain, bytes_sent, bytes_received, packet_count, is_orphaned, is_abnormal
                    ))
                
                result = cur.fetchone()
                conn.commit()
                return result[0] if result else 0
        except Exception as e:
            conn.rollback()
            logger.error(f"Error upserting traffic flow: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    def get_traffic_by_domain(
        self,
        domain: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get all traffic flows for a specific domain."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT * FROM traffic_flows
                    WHERE domain = %s
                """
                params = [domain]
                
                if start_time:
                    query += " AND last_update >= %s"
                    params.append(start_time)
                
                if end_time:
                    query += " AND last_update <= %s"
                    params.append(end_time)
                
                query += " ORDER BY last_update DESC"
                
                cur.execute(query, params)
                results = cur.fetchall()
                return [dict(r) for r in results]
        except Exception as e:
            logger.error(f"Error getting traffic by domain: {e}")
            return []
        finally:
            self._return_connection(conn)
    
    def get_orphaned_ips(
        self,
        days: int = 7,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get IPs that have traffic but no DNS entry in the last N days."""
        if not start_time:
            start_time = datetime.utcnow() - timedelta(days=days)
        if not end_time:
            end_time = datetime.utcnow()
        
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT 
                        destination_ip,
                        COALESCE(SUM(bytes_sent), 0) as total_bytes_sent,
                        COALESCE(SUM(bytes_received), 0) as total_bytes_received,
                        COALESCE(SUM(COALESCE(bytes_sent, 0) + COALESCE(bytes_received, 0)), 0) as total_bytes,
                        COALESCE(SUM(packet_count), 0) as total_packets,
                        COUNT(*) as connection_count,
                        MIN(first_seen) as first_seen,
                        MAX(last_update) as last_seen
                    FROM traffic_flows
                    WHERE is_orphaned = TRUE
                    AND last_update >= %s
                    AND last_update <= %s
                    GROUP BY destination_ip
                    ORDER BY total_bytes DESC
                """, (start_time, end_time))
                
                results = cur.fetchall()
                return [dict(r) for r in results]
        except Exception as e:
            logger.error(f"Error getting orphaned IPs: {e}")
            return []
        finally:
            self._return_connection(conn)
    
    def get_top_domains(
        self,
        limit: int = 10,
        offset: int = 0,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get top domains by traffic volume."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT 
                        COALESCE(domain, destination_ip::text) as domain,
                        COUNT(*) as query_count,
                        COALESCE(SUM(COALESCE(bytes_sent, 0) + COALESCE(bytes_received, 0)), 0) as total_bytes,
                        COALESCE(SUM(bytes_sent), 0) as bytes_sent,
                        COALESCE(SUM(bytes_received), 0) as bytes_received,
                        COALESCE(SUM(packet_count), 0) as total_packets,
                        MAX(last_update) as last_seen
                    FROM traffic_flows
                    WHERE 1=1
                """
                params = []
                
                if start_time:
                    query += " AND last_update >= %s"
                    params.append(start_time)
                
                if end_time:
                    query += " AND last_update <= %s"
                    params.append(end_time)
                
                query += """
                    GROUP BY COALESCE(domain, destination_ip::text)
                    ORDER BY total_bytes DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([limit, offset])
                
                cur.execute(query, params)
                results = cur.fetchall()
                # Convert to dicts and ensure numeric types are integers (PostgreSQL SUM returns NUMERIC)
                converted = []
                for r in results:
                    row_dict = dict(r)
                    # Ensure numeric fields are integers
                    if 'bytes_sent' in row_dict:
                        row_dict['bytes_sent'] = int(row_dict['bytes_sent'] or 0)
                    if 'bytes_received' in row_dict:
                        row_dict['bytes_received'] = int(row_dict['bytes_received'] or 0)
                    if 'total_bytes' in row_dict:
                        row_dict['total_bytes'] = int(row_dict['total_bytes'] or 0)
                    if 'total_packets' in row_dict:
                        row_dict['total_packets'] = int(row_dict['total_packets'] or 0)
                    if 'query_count' in row_dict:
                        row_dict['query_count'] = int(row_dict['query_count'] or 0)
                    converted.append(row_dict)
                return converted
        except Exception as e:
            logger.error(f"Error getting top domains: {e}")
            return []
        finally:
            self._return_connection(conn)
    
    def get_top_domains_count(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> int:
        """Get total count of domains for pagination."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                query = """
                    SELECT COUNT(DISTINCT COALESCE(domain, destination_ip::text)) as total
                    FROM traffic_flows
                    WHERE 1=1
                """
                params = []
                
                if start_time:
                    query += " AND last_update >= %s"
                    params.append(start_time)
                
                if end_time:
                    query += " AND last_update <= %s"
                    params.append(end_time)
                
                cur.execute(query, params)
                result = cur.fetchone()
                return result[0] if result else 0
        except Exception as e:
            logger.error(f"Error getting top domains count: {e}")
            return 0
        finally:
            self._return_connection(conn)
    
    def get_stats_per_domain_per_client(
        self,
        limit: int = 100,
        offset: int = 0,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        domain: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get statistics aggregated by flows (source_ip, destination_ip, destination_port, protocol).
        
        Groups traffic by flows (bidirectional) and counts both sent and received bytes.
        """
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT 
                        COALESCE(domain, destination_ip::text) as domain,
                        source_ip as client_ip,
                        destination_ip as server_ip,
                        destination_port as server_port,
                        protocol,
                        COUNT(*) as flow_count,
                        COALESCE(SUM(COALESCE(bytes_sent, 0) + COALESCE(bytes_received, 0)), 0) as total_bytes,
                        COALESCE(SUM(bytes_sent), 0) as bytes_sent,
                        COALESCE(SUM(bytes_received), 0) as bytes_received,
                        COALESCE(SUM(packet_count), 0) as total_packets,
                        MAX(last_update) as last_seen
                    FROM traffic_flows
                    WHERE 1=1
                """
                params = []
                
                if domain:
                    query += " AND domain = %s"
                    params.append(domain)
                
                if start_time:
                    query += " AND last_update >= %s"
                    params.append(start_time)
                
                if end_time:
                    query += " AND last_update <= %s"
                    params.append(end_time)
                
                query += """
                    GROUP BY source_ip, destination_ip, destination_port, protocol, COALESCE(domain, destination_ip::text)
                    ORDER BY total_bytes DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([limit, offset])
                
                cur.execute(query, params)
                results = cur.fetchall()
                # Convert to dicts and ensure numeric types are integers (PostgreSQL SUM returns NUMERIC)
                converted = []
                for r in results:
                    row_dict = dict(r)
                    # Ensure numeric fields are integers
                    if 'bytes_sent' in row_dict:
                        row_dict['bytes_sent'] = int(row_dict['bytes_sent'] or 0)
                    if 'bytes_received' in row_dict:
                        row_dict['bytes_received'] = int(row_dict['bytes_received'] or 0)
                    if 'total_bytes' in row_dict:
                        row_dict['total_bytes'] = int(row_dict['total_bytes'] or 0)
                    if 'total_packets' in row_dict:
                        row_dict['total_packets'] = int(row_dict['total_packets'] or 0)
                    if 'flow_count' in row_dict:
                        row_dict['flow_count'] = int(row_dict['flow_count'] or 0)
                    converted.append(row_dict)
                return converted
        except Exception as e:
            logger.error(f"Error getting stats per domain per client: {e}")
            return []
        finally:
            self._return_connection(conn)
    
    def get_stats_per_domain_per_client_count(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        domain: Optional[str] = None
    ) -> int:
        """Get total count of flows (source_ip, destination_ip, destination_port, protocol) for pagination."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                # Count distinct flows (source_ip, destination_ip, destination_port, protocol)
                query = """
                    SELECT COUNT(*) as total
                    FROM (
                        SELECT DISTINCT source_ip, destination_ip, destination_port, protocol
                        FROM traffic_flows
                        WHERE 1=1
                """
                params = []
                
                if domain:
                    query += " AND domain = %s"
                    params.append(domain)
                
                if start_time:
                    query += " AND last_update >= %s"
                    params.append(start_time)
                
                if end_time:
                    query += " AND last_update <= %s"
                    params.append(end_time)
                
                query += ")"
                
                cur.execute(query, params)
                result = cur.fetchone()
                return result[0] if result else 0
        except Exception as e:
            logger.error(f"Error getting stats per domain per client count: {e}")
            return 0
        finally:
            self._return_connection(conn)
    
    def get_dashboard_stats(
        self,
        hours: int = 24
    ) -> Dict[str, Any]:
        """Get dashboard statistics for the last N hours."""
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Total DNS queries
                cur.execute("""
                    SELECT COUNT(*) as count FROM dns_lookups
                    WHERE last_seen >= %s
                """, (start_time,))
                dns_queries = cur.fetchone()['count']
                
                # Total traffic volume
                cur.execute("""
                    SELECT 
                        SUM(bytes_sent + bytes_received) as total_bytes,
                        COUNT(*) as flow_count
                    FROM traffic_flows
                    WHERE last_update >= %s
                """, (start_time,))
                traffic_result = cur.fetchone()
                total_bytes = traffic_result['total_bytes'] or 0
                flow_count = traffic_result['flow_count'] or 0
                
                # Active connections (last hour)
                active_start = datetime.utcnow() - timedelta(hours=1)
                cur.execute("""
                    SELECT COUNT(DISTINCT destination_ip) as active_ips
                    FROM traffic_flows
                    WHERE last_update >= %s
                """, (active_start,))
                active_connections = cur.fetchone()['active_ips']
                
                return {
                    "dns_queries": dns_queries,
                    "total_bytes": total_bytes,
                    "flow_count": flow_count,
                    "active_connections": active_connections,
                    "period_hours": hours
                }
        except Exception as e:
            logger.error(f"Error getting dashboard stats: {e}")
            return {
                "dns_queries": 0,
                "total_bytes": 0,
                "flow_count": 0,
                "active_connections": 0,
                "period_hours": hours
            }
        finally:
            self._return_connection(conn)
    
    def save_whois_data(self, domain: str, whois_data: Dict[str, Any]) -> None:
        """Save WHOIS data for a domain."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO whois_data (domain, whois_data, whois_updated_at)
                    VALUES (%s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (domain)
                    DO UPDATE SET
                        whois_data = EXCLUDED.whois_data,
                        whois_updated_at = CURRENT_TIMESTAMP
                """, (domain, json.dumps(whois_data)))
                
                conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Error saving WHOIS data: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    def get_whois_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get WHOIS data for a domain."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM whois_data
                    WHERE domain = %s
                """, (domain,))
                
                result = cur.fetchone()
                if result:
                    return {
                        'domain': result['domain'],
                        'whois_data': result['whois_data'],
                        'whois_updated_at': result['whois_updated_at'],
                        'created_at': result['created_at']
                    }
                return None
        except Exception as e:
            logger.error(f"Error getting WHOIS data: {e}")
            return None
        finally:
            self._return_connection(conn)

    def insert_dns_event(
        self,
        event_type: str,
        domain: str,
        query_type: str,
        source_ip: str,
        destination_ip: str,
        resolved_ips: Optional[List[str]] = None,
        timestamp: Optional[datetime] = None
    ) -> int:
        if timestamp is None:
            timestamp = datetime.utcnow()
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO dns_events (
                        event_type, domain, query_type, source_ip, destination_ip, resolved_ips, event_timestamp
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (event_type, domain, query_type, source_ip, destination_ip, json.dumps(resolved_ips) if resolved_ips else None, timestamp)
                )
                rid = cur.fetchone()[0]
                conn.commit()
                return rid
        except Exception as e:
            conn.rollback()
            logger.error(f"Error inserting DNS event: {e}")
            raise
        finally:
            self._return_connection(conn)

    def get_dns_events(
        self,
        limit: int = 500,
        since: Optional[datetime] = None,
        source_ip: Optional[str] = None,
        domain: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                clauses = []
                params: List[Any] = []  # type: ignore
                if since:
                    clauses.append("event_timestamp >= %s")
                    params.append(since)
                if source_ip:
                    clauses.append("source_ip = %s")
                    params.append(source_ip)
                if domain:
                    clauses.append("domain = %s")
                    params.append(domain)
                if event_type:
                    clauses.append("event_type = %s")
                    params.append(event_type)
                where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
                sql = f"""
                    SELECT * FROM dns_events
                    {where_sql}
                    ORDER BY event_timestamp DESC
                    LIMIT %s
                """
                params.append(limit)
                cur.execute(sql, tuple(params))
                rows = cur.fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error fetching DNS events: {e}")
            return []
        finally:
            self._return_connection(conn)
    
    # User management methods
    def create_user(
        self,
        username: str,
        email: str,
        hashed_password: str,
        is_admin: bool = False,
        is_active: bool = True
    ) -> int:
        """Create a new user."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO users (username, email, hashed_password, is_admin, is_active)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                """, (username, email, hashed_password, is_admin, is_active))
                user_id = cur.fetchone()[0]
                conn.commit()
                return user_id
        except Exception as e:
            conn.rollback()
            logger.error(f"Error creating user: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM users WHERE username = %s
                """, (username,))
                result = cur.fetchone()
                if result:
                    return dict(result)
                return None
        except Exception as e:
            logger.error(f"Error getting user by username: {e}")
            return None
        finally:
            self._return_connection(conn)
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM users WHERE id = %s
                """, (user_id,))
                result = cur.fetchone()
                if result:
                    return dict(result)
                return None
        except Exception as e:
            logger.error(f"Error getting user by id: {e}")
            return None
        finally:
            self._return_connection(conn)
    
    def get_all_users(self, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all users with pagination."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM users
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (limit, skip))
                rows = cur.fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error getting all users: {e}")
            return []
        finally:
            self._return_connection(conn)
    
    def update_user(
        self,
        user_id: int,
        username: Optional[str] = None,
        email: Optional[str] = None,
        hashed_password: Optional[str] = None,
        is_admin: Optional[bool] = None,
        is_active: Optional[bool] = None
    ) -> bool:
        """Update user information."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                updates = []
                params = []
                
                if username is not None:
                    updates.append("username = %s")
                    params.append(username)
                if email is not None:
                    updates.append("email = %s")
                    params.append(email)
                if hashed_password is not None:
                    updates.append("hashed_password = %s")
                    params.append(hashed_password)
                if is_admin is not None:
                    updates.append("is_admin = %s")
                    params.append(is_admin)
                if is_active is not None:
                    updates.append("is_active = %s")
                    params.append(is_active)
                
                if not updates:
                    return False
                
                updates.append("updated_at = CURRENT_TIMESTAMP")
                params.append(user_id)
                
                cur.execute(f"""
                    UPDATE users
                    SET {', '.join(updates)}
                    WHERE id = %s
                """, tuple(params))
                conn.commit()
                return cur.rowcount > 0
        except Exception as e:
            conn.rollback()
            logger.error(f"Error updating user: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    def delete_user(self, user_id: int) -> bool:
        """Delete a user."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
                conn.commit()
                return cur.rowcount > 0
        except Exception as e:
            conn.rollback()
            logger.error(f"Error deleting user: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    # Threat intelligence operations
    def update_threat_indicators(
        self,
        feed_name: str,
        domains: List[str],
        ips: List[str],
        source_url: str
    ) -> int:
        """Update threat indicators for a feed (replace existing)."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                # Delete existing indicators for this feed
                cur.execute("DELETE FROM threat_indicators WHERE feed_name = %s", (feed_name,))
                
                # Insert domain indicators
                domain_values = [(feed_name, 'domain', domain.lower(), None) for domain in domains]
                if domain_values:
                    execute_values(
                        cur,
                        """INSERT INTO threat_indicators (feed_name, indicator_type, domain, ip)
                           VALUES %s""",
                        domain_values
                    )
                
                # Insert IP indicators
                ip_values = [(feed_name, 'ip', None, ip) for ip in ips]
                if ip_values:
                    execute_values(
                        cur,
                        """INSERT INTO threat_indicators (feed_name, indicator_type, domain, ip)
                           VALUES %s""",
                        ip_values
                    )
                
                conn.commit()
                total_count = len(domains) + len(ips)
                logger.info(f"Updated {total_count} indicators for feed {feed_name} ({len(domains)} domains, {len(ips)} IPs)")
                return total_count
        except Exception as e:
            conn.rollback()
            logger.error(f"Error updating threat indicators: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    def check_threat_indicator(
        self,
        domain: Optional[str] = None,
        ip: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Check if a domain or IP matches a threat indicator."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if domain:
                    # Check exact domain match
                    cur.execute("""
                        SELECT feed_name, indicator_type, domain, ip, first_seen, last_seen
                        FROM threat_indicators
                        WHERE indicator_type = 'domain' AND domain = %s
                        LIMIT 1
                    """, (domain.lower(),))
                    row = cur.fetchone()
                    if row:
                        return dict(row)
                elif ip:
                    # Check IP match
                    cur.execute("""
                        SELECT feed_name, indicator_type, domain, ip, first_seen, last_seen
                        FROM threat_indicators
                        WHERE indicator_type = 'ip' AND ip = %s
                        LIMIT 1
                    """, (ip,))
                    row = cur.fetchone()
                    if row:
                        return dict(row)
                return None
        except Exception as e:
            logger.error(f"Error checking threat indicator: {e}")
            return None
        finally:
            self._return_connection(conn)
    
    def create_threat_alert(
        self,
        domain: Optional[str],
        ip: Optional[str],
        query_type: str,
        source_ip: str,
        threat_feed: str,
        indicator_type: str
    ) -> int:
        """Create a threat alert."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO threat_alerts 
                    (feed_name, indicator_type, domain, ip, query_type, source_ip)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (threat_feed, indicator_type, domain.lower() if domain else None, ip, query_type, source_ip))
                alert_id = cur.fetchone()[0]
                conn.commit()
                logger.warning(f"Threat alert created: {indicator_type} match - {domain or ip} from {source_ip} (feed: {threat_feed})")
                return alert_id
        except Exception as e:
            conn.rollback()
            logger.error(f"Error creating threat alert: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    def get_threat_alerts(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
        resolved: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """Get threat alerts."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = "SELECT * FROM threat_alerts WHERE 1=1"
                params = []
                
                if since:
                    query += " AND created_at >= %s"
                    params.append(since)
                
                if resolved is not None:
                    query += " AND resolved = %s"
                    params.append(resolved)
                
                query += " ORDER BY created_at DESC LIMIT %s"
                params.append(limit)
                
                cur.execute(query, tuple(params))
                rows = cur.fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error getting threat alerts: {e}")
            return []
        finally:
            self._return_connection(conn)
    
    def get_threat_alerts_count(
        self,
        since: Optional[datetime] = None,
        resolved: Optional[bool] = None
    ) -> int:
        """Get total count of threat alerts."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                query = "SELECT COUNT(*) FROM threat_alerts WHERE 1=1"
                params = []
                
                if since:
                    query += " AND created_at >= %s"
                    params.append(since)
                
                if resolved is not None:
                    query += " AND resolved = %s"
                    params.append(resolved)
                
                cur.execute(query, tuple(params))
                result = cur.fetchone()
                return int(result[0]) if result else 0
        except Exception as e:
            logger.error(f"Error getting threat alerts count: {e}")
            return 0
        finally:
            self._return_connection(conn)
    
    def get_threat_feeds(self) -> List[Dict[str, Any]]:
        """Get list of threat feeds."""
        conn = self._get_connection()
        try:
            import json
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM threat_feeds ORDER BY feed_name")
                rows = cur.fetchall()
                result = []
                for row in rows:
                    feed_dict = dict(row)
                    # Parse config JSON if present
                    if feed_dict.get('config') and isinstance(feed_dict['config'], str):
                        try:
                            feed_dict['config'] = json.loads(feed_dict['config'])
                        except (json.JSONDecodeError, TypeError):
                            feed_dict['config'] = None
                    elif feed_dict.get('config') is None:
                        feed_dict['config'] = None
                    result.append(feed_dict)
                return result
        except Exception as e:
            logger.error(f"Error getting threat feeds: {e}")
            return []
        finally:
            self._return_connection(conn)
    
    def update_threat_feed_metadata(
        self,
        feed_name: str,
        last_update: Optional[datetime],
        indicator_count: int,
        source_url: str,
        enabled: bool = True,
        error: Optional[str] = None,
        homepage: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> None:
        """Update threat feed metadata."""
        conn = self._get_connection()
        try:
            import json
            config_json = json.dumps(config) if config else None
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO threat_feeds (feed_name, source_url, enabled, last_update, indicator_count, last_error, homepage, config, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (feed_name) DO UPDATE SET
                        source_url = EXCLUDED.source_url,
                        enabled = EXCLUDED.enabled,
                        last_update = EXCLUDED.last_update,
                        indicator_count = EXCLUDED.indicator_count,
                        last_error = EXCLUDED.last_error,
                        homepage = EXCLUDED.homepage,
                        config = EXCLUDED.config,
                        updated_at = CURRENT_TIMESTAMP
                """, (feed_name, source_url, enabled, last_update, indicator_count, error, homepage, config_json))
                conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Error updating threat feed metadata: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    def resolve_threat_alert(self, alert_id: int) -> bool:
        """Mark a threat alert as resolved."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE threat_alerts
                    SET resolved = TRUE, resolved_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (alert_id,))
                conn.commit()
                return cur.rowcount > 0
        except Exception as e:
            conn.rollback()
            logger.error(f"Error resolving threat alert: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    def resolve_threat_alerts_by_indicator(
        self,
        domain: Optional[str] = None,
        ip: Optional[str] = None
    ) -> int:
        """Resolve all threat alerts matching a domain or IP."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                query = """
                    UPDATE threat_alerts
                    SET resolved = TRUE, resolved_at = CURRENT_TIMESTAMP
                    WHERE resolved = FALSE AND (
                """
                params = []
                
                if domain:
                    query += " domain = %s"
                    params.append(domain.lower())
                
                if ip:
                    if domain:
                        query += " OR ip = %s"
                    else:
                        query += " ip = %s"
                    params.append(ip)
                
                query += " )"
                
                cur.execute(query, tuple(params))
                conn.commit()
                return cur.rowcount
        except Exception as e:
            conn.rollback()
            logger.error(f"Error resolving threat alerts by indicator: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    def update_threat_feed_enabled(self, feed_name: str, enabled: bool) -> bool:
        """Update the enabled status of a threat feed."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE threat_feeds
                    SET enabled = %s, updated_at = CURRENT_TIMESTAMP
                    WHERE feed_name = %s
                """, (enabled, feed_name))
                conn.commit()
                return cur.rowcount > 0
        except Exception as e:
            conn.rollback()
            logger.error(f"Error updating threat feed enabled status: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    # Threat whitelist operations
    def add_threat_whitelist(
        self,
        indicator_type: str,
        domain: Optional[str] = None,
        ip: Optional[str] = None,
        reason: Optional[str] = None
    ) -> int:
        """Add an indicator to the threat whitelist."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                # Check if entry already exists
                if domain:
                    cur.execute("""
                        SELECT id FROM threat_whitelist
                        WHERE indicator_type = %s AND domain = %s
                        LIMIT 1
                    """, (indicator_type, domain.lower()))
                    existing = cur.fetchone()
                    if existing:
                        return existing[0]
                elif ip:
                    cur.execute("""
                        SELECT id FROM threat_whitelist
                        WHERE indicator_type = %s AND ip = %s
                        LIMIT 1
                    """, (indicator_type, ip))
                    existing = cur.fetchone()
                    if existing:
                        return existing[0]
                
                # Insert new entry
                cur.execute("""
                    INSERT INTO threat_whitelist (indicator_type, domain, ip, reason)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                """, (indicator_type, domain.lower() if domain else None, ip, reason))
                result = cur.fetchone()
                if result:
                    conn.commit()
                    return result[0]
                raise ValueError("Failed to add whitelist entry")
        except Exception as e:
            conn.rollback()
            logger.error(f"Error adding threat whitelist entry: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    def remove_threat_whitelist(self, whitelist_id: int) -> bool:
        """Remove an indicator from the threat whitelist."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM threat_whitelist WHERE id = %s", (whitelist_id,))
                conn.commit()
                return cur.rowcount > 0
        except Exception as e:
            conn.rollback()
            logger.error(f"Error removing threat whitelist entry: {e}")
            raise
        finally:
            self._return_connection(conn)
    
    def get_threat_whitelist(
        self,
        limit: int = 100,
        indicator_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get threat whitelist entries."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = "SELECT * FROM threat_whitelist WHERE 1=1"
                params = []
                
                if indicator_type:
                    query += " AND indicator_type = %s"
                    params.append(indicator_type)
                
                query += " ORDER BY created_at DESC LIMIT %s"
                params.append(limit)
                
                cur.execute(query, tuple(params))
                rows = cur.fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error getting threat whitelist: {e}")
            return []
        finally:
            self._return_connection(conn)
    
    def is_threat_whitelisted(
        self,
        domain: Optional[str] = None,
        ip: Optional[str] = None
    ) -> bool:
        """Check if a domain or IP is whitelisted."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                if domain:
                    # Normalize domain
                    domain_lower = domain.lower().strip()
                    if not domain_lower:
                        return False
                    
                    # Check exact match
                    cur.execute("""
                        SELECT 1 FROM threat_whitelist
                        WHERE indicator_type = 'domain' AND domain = %s
                        LIMIT 1
                    """, (domain_lower,))
                    if cur.fetchone():
                        logger.debug(f"Whitelist exact match found for domain: {domain_lower}")
                        return True
                    
                    # Check if domain is a subdomain of a whitelisted domain
                    parts = domain_lower.split('.')
                    for i in range(1, len(parts)):
                        parent_domain = '.'.join(parts[i:])
                        if len(parent_domain.split('.')) >= 2:
                            cur.execute("""
                                SELECT 1 FROM threat_whitelist
                                WHERE indicator_type = 'domain' AND domain = %s
                                LIMIT 1
                            """, (parent_domain,))
                            if cur.fetchone():
                                logger.debug(f"Whitelist parent domain match found: {parent_domain} for {domain_lower}")
                                return True
                    
                    return False
                elif ip:
                    # Normalize IP
                    ip_str = str(ip).strip() if ip else None
                    if not ip_str:
                        return False
                    
                    # Check exact match in whitelist
                    cur.execute("""
                        SELECT 1 FROM threat_whitelist
                        WHERE indicator_type = 'ip' AND ip = %s
                        LIMIT 1
                    """, (ip_str,))
                    result = cur.fetchone() is not None
                    if result:
                        logger.debug(f"Whitelist exact match found for IP: {ip_str}")
                    return result
                return False
        except Exception as e:
            logger.error(f"Error checking threat whitelist: {e}", exc_info=True)
            return False
        finally:
            self._return_connection(conn)
    
    # Settings operations
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get an application setting."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT value FROM settings WHERE key = %s", (key,))
                result = cur.fetchone()
                if result:
                    try:
                        # Try to parse as JSON
                        return json.loads(result[0])
                    except (json.JSONDecodeError, TypeError):
                        # Return as string if not JSON
                        return result[0]
                return default
        except Exception as e:
            logger.error(f"Error getting setting {key}: {e}")
            return default
        finally:
            self._return_connection(conn)
    
    def set_setting(self, key: str, value: Any) -> None:
        """Set an application setting."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                # Convert value to JSON string if not already a string
                if not isinstance(value, str):
                    value_str = json.dumps(value)
                else:
                    value_str = value
                
                cur.execute("""
                    INSERT INTO settings (key, value, updated_at)
                    VALUES (%s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (key) DO UPDATE SET
                        value = EXCLUDED.value,
                        updated_at = CURRENT_TIMESTAMP
                """, (key, value_str))
                conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Error setting {key}: {e}")
            raise
        finally:
            self._return_connection(conn)

