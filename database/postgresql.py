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
                password=self.db_config.password
            )
            logger.info("Connected to PostgreSQL database")
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
        return self.connection_pool.getconn()
    
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
                        UNIQUE(source_ip, destination_ip, destination_port, protocol)
                    )
                """)
                
                # Create indexes
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flow_source ON traffic_flows(source_ip)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flow_dest ON traffic_flows(destination_ip)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flow_dest_port ON traffic_flows(destination_port)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flow_domain ON traffic_flows(domain)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flow_orphaned ON traffic_flows(is_orphaned)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flow_timestamp ON traffic_flows(last_update)")
                
                # Threat Indicators table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS threat_indicators (
                        id SERIAL PRIMARY KEY,
                        indicator_type VARCHAR(50) NOT NULL,
                        source_ip INET,
                        destination_ip INET,
                        domain VARCHAR(255),
                        severity VARCHAR(20) NOT NULL,
                        description TEXT,
                        detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_indicators(indicator_type)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_severity ON threat_indicators(severity)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_detected ON threat_indicators(detected_at)")
                
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
    
    def get_dns_lookup_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get DNS lookup information by domain."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM dns_lookups
                    WHERE domain = %s
                    ORDER BY last_seen DESC
                    LIMIT 1
                """, (domain,))
                
                result = cur.fetchone()
                return dict(result) if result else None
        except Exception as e:
            logger.error(f"Error getting DNS lookup: {e}")
            return None
        finally:
            self._return_connection(conn)
    
    def get_domain_by_ip(self, ip: str, days: int = 7) -> Optional[str]:
        """Get domain name for an IP address if it was resolved in the last N days."""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT domain FROM dns_lookups
                    WHERE resolved_ips @> %s::jsonb
                    AND last_seen >= %s
                    ORDER BY last_seen DESC
                    LIMIT 1
                """, (json.dumps([ip]), cutoff_date))
                
                result = cur.fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.error(f"Error getting domain by IP: {e}")
            return None
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
        domain: Optional[str] = None
    ) -> int:
        """Insert or update a traffic flow entry."""
        # Check if domain exists for this IP
        if not domain:
            domain = self.get_domain_by_ip(destination_ip, config.orphaned_ip_days)
        
        is_orphaned = domain is None
        
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO traffic_flows (
                        source_ip, destination_ip, destination_port, protocol,
                        domain, bytes_sent, bytes_received, packet_count, is_orphaned
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (source_ip, destination_ip, destination_port, protocol)
                    DO UPDATE SET
                        bytes_sent = traffic_flows.bytes_sent + EXCLUDED.bytes_sent,
                        bytes_received = traffic_flows.bytes_received + EXCLUDED.bytes_received,
                        packet_count = traffic_flows.packet_count + EXCLUDED.packet_count,
                        last_update = CURRENT_TIMESTAMP,
                        domain = COALESCE(traffic_flows.domain, EXCLUDED.domain),
                        is_orphaned = EXCLUDED.is_orphaned
                    RETURNING id
                """, (
                    source_ip, destination_ip, destination_port, protocol,
                    domain, bytes_sent, bytes_received, packet_count, is_orphaned
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
                        SUM(bytes_sent) as total_bytes_sent,
                        SUM(bytes_received) as total_bytes_received,
                        SUM(bytes_sent + bytes_received) as total_bytes,
                        SUM(packet_count) as total_packets,
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
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get top domains by traffic volume."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT 
                        domain,
                        COUNT(*) as query_count,
                        SUM(bytes_sent + bytes_received) as total_bytes,
                        SUM(bytes_sent) as bytes_sent,
                        SUM(bytes_received) as bytes_received,
                        SUM(packet_count) as total_packets,
                        MAX(last_update) as last_seen
                    FROM traffic_flows
                    WHERE domain IS NOT NULL
                """
                params = []
                
                if start_time:
                    query += " AND last_update >= %s"
                    params.append(start_time)
                
                if end_time:
                    query += " AND last_update <= %s"
                    params.append(end_time)
                
                query += """
                    GROUP BY domain
                    ORDER BY total_bytes DESC
                    LIMIT %s
                """
                params.append(limit)
                
                cur.execute(query, params)
                results = cur.fetchall()
                return [dict(r) for r in results]
        except Exception as e:
            logger.error(f"Error getting top domains: {e}")
            return []
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

