"""SQLite database implementation."""
import sqlite3
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import json
import logging

from .base import DatabaseBase
from config import config

logger = logging.getLogger(__name__)


class SQLiteDatabase(DatabaseBase):
    """SQLite implementation of database operations."""
    
    def __init__(self):
        """Initialize SQLite connection."""
        self.db_path = config.database.name if config.database.name.endswith('.db') else f"{config.database.name}.db"
        self.conn = None
    
    def connect(self) -> None:
        """Establish database connection."""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            logger.info(f"Connected to SQLite database: {self.db_path}")
        except Exception as e:
            logger.error(f"Error connecting to database: {e}")
            raise
    
    def disconnect(self) -> None:
        """Close database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Disconnected from SQLite database")
    
    def create_tables(self) -> None:
        """Create all required database tables."""
        if not self.conn:
            self.connect()
        
        try:
            cursor = self.conn.cursor()
            
            # DNS Lookups table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_lookups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    query_type TEXT NOT NULL,
                    resolved_ips TEXT NOT NULL,
                    query_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain, query_type)
                )
            """)
            
            # Add first_seen column if it doesn't exist
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='dns_lookups'
            """)
            if cursor.fetchone():
                cursor.execute("""
                    SELECT COUNT(*) FROM pragma_table_info('dns_lookups') WHERE name='first_seen'
                """)
                if cursor.fetchone()[0] == 0:
                    cursor.execute("ALTER TABLE dns_lookups ADD COLUMN first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_lookups(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_lookups(query_timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_first_seen ON dns_lookups(first_seen)")
            
            # Traffic Flows table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    destination_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    domain TEXT,
                    bytes_sent INTEGER NOT NULL DEFAULT 0,
                    bytes_received INTEGER NOT NULL DEFAULT 0,
                    packet_count INTEGER NOT NULL DEFAULT 0,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_update TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    is_orphaned INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(source_ip, destination_ip, destination_port, protocol)
                )
            """)
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flow_source ON traffic_flows(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flow_dest ON traffic_flows(destination_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flow_dest_port ON traffic_flows(destination_port)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flow_domain ON traffic_flows(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flow_orphaned ON traffic_flows(is_orphaned)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flow_timestamp ON traffic_flows(last_update)")
            
            # Threat Indicators table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_type TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    domain TEXT,
                    severity TEXT NOT NULL,
                    description TEXT,
                    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_indicators(indicator_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_severity ON threat_indicators(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_detected ON threat_indicators(detected_at)")
            
            # WHOIS Data table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS whois_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    whois_data TEXT NOT NULL,
                    whois_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_whois_domain ON whois_data(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_whois_updated ON whois_data(whois_updated_at)")

            # DNS Events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL, -- 'query' or 'response'
                    domain TEXT NOT NULL,
                    query_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    resolved_ips TEXT,
                    event_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dnsevents_time ON dns_events(event_timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dnsevents_domain ON dns_events(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dnsevents_src ON dns_events(source_ip)")
            
            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    hashed_password TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            
            # Threat Feeds table (metadata about threat intelligence feeds)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_feeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feed_name TEXT NOT NULL UNIQUE,
                    source_url TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_update TIMESTAMP,
                    indicator_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_feeds_name ON threat_feeds(feed_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_feeds_enabled ON threat_feeds(enabled)")
            
            # Threat Indicators table (actual domains and IPs from feeds)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feed_name TEXT NOT NULL,
                    indicator_type TEXT NOT NULL, -- 'domain' or 'ip'
                    domain TEXT,
                    ip TEXT,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(feed_name, indicator_type, COALESCE(domain, ''), COALESCE(ip, ''))
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_ind_feed ON threat_indicators(feed_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_ind_type ON threat_indicators(indicator_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_ind_domain ON threat_indicators(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_ind_ip ON threat_indicators(ip)")
            
            # Threat Alerts table (alerts when matches are detected)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feed_name TEXT NOT NULL,
                    indicator_type TEXT NOT NULL, -- 'domain' or 'ip'
                    domain TEXT,
                    ip TEXT,
                    query_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    resolved INTEGER NOT NULL DEFAULT 0,
                    resolved_at TIMESTAMP,
                    resolved_by INTEGER,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_alerts_feed ON threat_alerts(feed_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_alerts_resolved ON threat_alerts(resolved)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_alerts_created ON threat_alerts(created_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_alerts_domain ON threat_alerts(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_alerts_ip ON threat_alerts(ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_alerts_src ON threat_alerts(source_ip)")

            self.conn.commit()
            logger.info("Database tables created successfully")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"Error creating tables: {e}")
            raise
    
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
        
        if not self.conn:
            self.connect()
        
        try:
            cursor = self.conn.cursor()
            # Check if domain already exists to preserve first_seen
            cursor.execute("""
                SELECT first_seen FROM dns_lookups
                WHERE domain = ? AND query_type = ?
            """, (domain, query_type))
            
            existing = cursor.fetchone()
            if existing:
                first_seen = existing[0]  # Preserve original first_seen
            
            cursor.execute("""
                INSERT INTO dns_lookups 
                (domain, query_type, resolved_ips, query_timestamp, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (domain, query_type)
                DO UPDATE SET
                    resolved_ips = excluded.resolved_ips,
                    last_seen = excluded.last_seen
            """, (domain, query_type, json.dumps(resolved_ips), timestamp, first_seen, timestamp))
            
            self.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error inserting DNS lookup: {e}")
            raise

    def get_recent_dns_queries(self, limit: int = 100, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get recent DNS queries ordered by last_seen desc."""
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            if since:
                cursor.execute(
                    """
                    SELECT * FROM dns_lookups
                    WHERE last_seen >= ?
                    ORDER BY last_seen DESC
                    LIMIT ?
                    """,
                    (since, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM dns_lookups
                    ORDER BY last_seen DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error getting recent DNS queries: {e}")
            return []
    
    def get_dns_lookup_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get DNS lookup information by domain."""
        if not self.conn:
            self.connect()
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT * FROM dns_lookups
                WHERE domain = ?
                ORDER BY last_seen DESC
                LIMIT 1
            """,
                (domain,),
            )
            
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Error getting DNS lookup: {e}")
            return None
    
    def get_domain_by_ip(self, ip: str, days: int = 7) -> Optional[str]:
        """Get domain name for an IP address if it was resolved in the last N days."""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        if not self.conn:
            self.connect()
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT domain FROM dns_lookups
                WHERE json_extract(resolved_ips, '$') LIKE ?
                AND last_seen >= ?
                ORDER BY last_seen DESC
                LIMIT 1
            """, (f'%{ip}%', cutoff_date))
            
            result = cursor.fetchone()
            return result[0] if result else None
        except Exception as e:
            logger.error(f"Error getting domain by IP: {e}")
            return None
    
    def search_domains(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search for domains matching a query string."""
        if not self.conn:
            self.connect()
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM dns_lookups
                WHERE domain LIKE ?
                ORDER BY last_seen DESC
                LIMIT ?
            """, (f"%{query}%", limit))
            
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error searching domains: {e}")
            return []
    
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
        if not domain:
            domain = self.get_domain_by_ip(destination_ip, config.orphaned_ip_days)
        
        is_orphaned = 1 if domain is None else 0
        
        if not self.conn:
            self.connect()
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO traffic_flows (
                    source_ip, destination_ip, destination_port, protocol,
                    domain, bytes_sent, bytes_received, packet_count, is_orphaned
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (source_ip, destination_ip, destination_port, protocol)
                DO UPDATE SET
                    bytes_sent = bytes_sent + excluded.bytes_sent,
                    bytes_received = bytes_received + excluded.bytes_received,
                    packet_count = packet_count + excluded.packet_count,
                    last_update = CURRENT_TIMESTAMP,
                    domain = COALESCE(domain, excluded.domain),
                    is_orphaned = excluded.is_orphaned
            """, (
                source_ip, destination_ip, destination_port, protocol,
                domain, bytes_sent, bytes_received, packet_count, is_orphaned
            ))
            
            self.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error upserting traffic flow: {e}")
            raise
    
    def get_traffic_by_domain(
        self,
        domain: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get all traffic flows for a specific domain."""
        if not self.conn:
            self.connect()
        
        try:
            cursor = self.conn.cursor()
            query = """
                SELECT * FROM traffic_flows
                WHERE domain = ?
            """
            params = [domain]
            
            if start_time:
                query += " AND last_update >= ?"
                params.append(start_time)
            
            if end_time:
                query += " AND last_update <= ?"
                params.append(end_time)
            
            query += " ORDER BY last_update DESC"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error getting traffic by domain: {e}")
            return []
    
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
        
        if not self.conn:
            self.connect()
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
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
                WHERE is_orphaned = 1
                AND last_update >= ?
                AND last_update <= ?
                GROUP BY destination_ip
                ORDER BY total_bytes DESC
            """, (start_time, end_time))
            
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error getting orphaned IPs: {e}")
            return []
    
    def get_top_domains(
        self,
        limit: int = 10,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get top domains by traffic volume."""
        if not self.conn:
            self.connect()
        
        try:
            cursor = self.conn.cursor()
            query = """
                SELECT 
                    COALESCE(domain, destination_ip) as domain,
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
                query += " AND last_update >= ?"
                params.append(start_time)
            
            if end_time:
                query += " AND last_update <= ?"
                params.append(end_time)
            
            query += """
                GROUP BY COALESCE(domain, destination_ip)
                ORDER BY total_bytes DESC
                LIMIT ?
            """
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error getting top domains: {e}")
            return []
    
    def get_dashboard_stats(
        self,
        hours: int = 24
    ) -> Dict[str, Any]:
        """Get dashboard statistics for the last N hours."""
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        if not self.conn:
            self.connect()
        
        try:
            cursor = self.conn.cursor()
            
            # Total DNS queries
            cursor.execute("""
                SELECT COUNT(*) as count FROM dns_lookups
                WHERE last_seen >= ?
            """, (start_time,))
            dns_queries = cursor.fetchone()[0]
            
            # Total traffic volume
            cursor.execute("""
                SELECT 
                    SUM(bytes_sent + bytes_received) as total_bytes,
                    COUNT(*) as flow_count
                FROM traffic_flows
                WHERE last_update >= ?
            """, (start_time,))
            traffic_result = cursor.fetchone()
            total_bytes = traffic_result[0] or 0
            flow_count = traffic_result[1] or 0
            
            # Active connections (last hour)
            active_start = datetime.utcnow() - timedelta(hours=1)
            cursor.execute("""
                SELECT COUNT(DISTINCT destination_ip) as active_ips
                FROM traffic_flows
                WHERE last_update >= ?
            """, (active_start,))
            active_connections = cursor.fetchone()[0]
            
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
    
    def save_whois_data(self, domain: str, whois_data: Dict[str, Any]) -> None:
        """Save WHOIS data for a domain."""
        if not self.conn:
            self.connect()
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO whois_data (domain, whois_data, whois_updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT (domain)
                DO UPDATE SET
                    whois_data = excluded.whois_data,
                    whois_updated_at = CURRENT_TIMESTAMP
            """, (domain, json.dumps(whois_data)))
            
            self.conn.commit()
        except Exception as e:
            logger.error(f"Error saving WHOIS data: {e}")
            raise
    
    def get_whois_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get WHOIS data for a domain."""
        if not self.conn:
            self.connect()
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM whois_data
                WHERE domain = ?
            """, (domain,))
            
            row = cursor.fetchone()
            if row:
                return {
                    'domain': row[1],
                    'whois_data': json.loads(row[2]) if isinstance(row[2], str) else row[2],
                    'whois_updated_at': row[3],
                    'created_at': row[4]
                }
            return None
        except Exception as e:
            logger.error(f"Error getting WHOIS data: {e}")
            return None

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
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO dns_events (
                    event_type, domain, query_type, source_ip, destination_ip, resolved_ips, event_timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_type, domain, query_type, source_ip, destination_ip,
                    json.dumps(resolved_ips) if resolved_ips else None,
                    timestamp,
                ),
            )
            self.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error inserting DNS event: {e}")
            raise

    def get_dns_events(
        self,
        limit: int = 500,
        since: Optional[datetime] = None,
        source_ip: Optional[str] = None,
        domain: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            clauses = []
            params: List[Any] = []  # type: ignore
            if since:
                clauses.append("event_timestamp >= ?")
                params.append(since)
            if source_ip:
                clauses.append("source_ip = ?")
                params.append(source_ip)
            if domain:
                clauses.append("domain = ?")
                params.append(domain)
            if event_type:
                clauses.append("event_type = ?")
                params.append(event_type)
            where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
            sql = f"""
                SELECT * FROM dns_events
                {where_sql}
                ORDER BY event_timestamp DESC
                LIMIT ?
            """
            params.append(limit)
            cursor.execute(sql, tuple(params))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error fetching DNS events: {e}")
            return []
    
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
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, email, hashed_password, is_admin, is_active)
                VALUES (?, ?, ?, ?, ?)
            """, (username, email, hashed_password, 1 if is_admin else 0, 1 if is_active else 0))
            self.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            raise
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM users WHERE username = ?
            """, (username,))
            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0],
                    'username': row[1],
                    'email': row[2],
                    'hashed_password': row[3],
                    'is_admin': bool(row[4]),
                    'is_active': bool(row[5]),
                    'created_at': row[6],
                    'updated_at': row[7]
                }
            return None
        except Exception as e:
            logger.error(f"Error getting user by username: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM users WHERE id = ?
            """, (user_id,))
            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0],
                    'username': row[1],
                    'email': row[2],
                    'hashed_password': row[3],
                    'is_admin': bool(row[4]),
                    'is_active': bool(row[5]),
                    'created_at': row[6],
                    'updated_at': row[7]
                }
            return None
        except Exception as e:
            logger.error(f"Error getting user by id: {e}")
            return None
    
    def get_all_users(self, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all users with pagination."""
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM users
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, (limit, skip))
            rows = cursor.fetchall()
            return [{
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'hashed_password': row[3],
                'is_admin': bool(row[4]),
                'is_active': bool(row[5]),
                'created_at': row[6],
                'updated_at': row[7]
            } for row in rows]
        except Exception as e:
            logger.error(f"Error getting all users: {e}")
            return []
    
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
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            updates = []
            params = []
            
            if username is not None:
                updates.append("username = ?")
                params.append(username)
            if email is not None:
                updates.append("email = ?")
                params.append(email)
            if hashed_password is not None:
                updates.append("hashed_password = ?")
                params.append(hashed_password)
            if is_admin is not None:
                updates.append("is_admin = ?")
                params.append(1 if is_admin else 0)
            if is_active is not None:
                updates.append("is_active = ?")
                params.append(1 if is_active else 0)
            
            if not updates:
                return False
            
            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.append(user_id)
            
            cursor.execute(f"""
                UPDATE users
                SET {', '.join(updates)}
                WHERE id = ?
            """, tuple(params))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error updating user: {e}")
            raise
    
    def delete_user(self, user_id: int) -> bool:
        """Delete a user."""
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            raise
    
    # Threat intelligence operations
    def update_threat_indicators(
        self,
        feed_name: str,
        domains: List[str],
        ips: List[str],
        source_url: str
    ) -> int:
        """Update threat indicators for a feed (replace existing)."""
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            # Delete existing indicators for this feed
            cursor.execute("DELETE FROM threat_indicators WHERE feed_name = ?", (feed_name,))
            
            # Insert domain indicators
            domain_values = [(feed_name, 'domain', domain.lower(), None) for domain in domains]
            if domain_values:
                cursor.executemany(
                    """INSERT OR IGNORE INTO threat_indicators 
                       (feed_name, indicator_type, domain, ip)
                       VALUES (?, ?, ?, ?)""",
                    domain_values
                )
            
            # Insert IP indicators
            ip_values = [(feed_name, 'ip', None, ip) for ip in ips]
            if ip_values:
                cursor.executemany(
                    """INSERT OR IGNORE INTO threat_indicators 
                       (feed_name, indicator_type, domain, ip)
                       VALUES (?, ?, ?, ?)""",
                    ip_values
                )
            
            self.conn.commit()
            total_count = len(domains) + len(ips)
            logger.info(f"Updated {total_count} indicators for feed {feed_name} ({len(domains)} domains, {len(ips)} IPs)")
            return total_count
        except Exception as e:
            logger.error(f"Error updating threat indicators: {e}")
            raise
    
    def check_threat_indicator(
        self,
        domain: Optional[str] = None,
        ip: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Check if a domain or IP matches a threat indicator."""
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            if domain:
                cursor.execute("""
                    SELECT feed_name, indicator_type, domain, ip, first_seen, last_seen
                    FROM threat_indicators
                    WHERE indicator_type = 'domain' AND domain = ?
                    LIMIT 1
                """, (domain.lower(),))
                row = cursor.fetchone()
                if row:
                    return {
                        'feed_name': row[0],
                        'indicator_type': row[1],
                        'domain': row[2],
                        'ip': row[3],
                        'first_seen': row[4],
                        'last_seen': row[5]
                    }
            elif ip:
                cursor.execute("""
                    SELECT feed_name, indicator_type, domain, ip, first_seen, last_seen
                    FROM threat_indicators
                    WHERE indicator_type = 'ip' AND ip = ?
                    LIMIT 1
                """, (ip,))
                row = cursor.fetchone()
                if row:
                    return {
                        'feed_name': row[0],
                        'indicator_type': row[1],
                        'domain': row[2],
                        'ip': row[3],
                        'first_seen': row[4],
                        'last_seen': row[5]
                    }
            return None
        except Exception as e:
            logger.error(f"Error checking threat indicator: {e}")
            return None
    
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
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO threat_alerts 
                (feed_name, indicator_type, domain, ip, query_type, source_ip)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (threat_feed, indicator_type, domain.lower() if domain else None, ip, query_type, source_ip))
            self.conn.commit()
            alert_id = cursor.lastrowid
            logger.warning(f"Threat alert created: {indicator_type} match - {domain or ip} from {source_ip} (feed: {threat_feed})")
            return alert_id
        except Exception as e:
            logger.error(f"Error creating threat alert: {e}")
            raise
    
    def get_threat_alerts(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
        resolved: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """Get threat alerts."""
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            query = "SELECT * FROM threat_alerts WHERE 1=1"
            params = []
            
            if since:
                query += " AND created_at >= ?"
                params.append(since)
            
            if resolved is not None:
                query += " AND resolved = ?"
                params.append(1 if resolved else 0)
            
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            
            # Convert rows to dicts
            columns = [description[0] for description in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        except Exception as e:
            logger.error(f"Error getting threat alerts: {e}")
            return []
    
    def get_threat_feeds(self) -> List[Dict[str, Any]]:
        """Get list of threat feeds."""
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM threat_feeds ORDER BY feed_name")
            rows = cursor.fetchall()
            
            columns = [description[0] for description in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        except Exception as e:
            logger.error(f"Error getting threat feeds: {e}")
            return []
    
    def update_threat_feed_metadata(
        self,
        feed_name: str,
        last_update: datetime,
        indicator_count: int,
        source_url: str,
        enabled: bool = True,
        error: Optional[str] = None
    ) -> None:
        """Update threat feed metadata."""
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO threat_feeds (feed_name, source_url, enabled, last_update, indicator_count, last_error, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(feed_name) DO UPDATE SET
                    source_url = EXCLUDED.source_url,
                    enabled = EXCLUDED.enabled,
                    last_update = EXCLUDED.last_update,
                    indicator_count = EXCLUDED.indicator_count,
                    last_error = EXCLUDED.last_error,
                    updated_at = CURRENT_TIMESTAMP
            """, (feed_name, source_url, 1 if enabled else 0, last_update, indicator_count, error))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Error updating threat feed metadata: {e}")
            raise
    
    def resolve_threat_alert(self, alert_id: int) -> bool:
        """Mark a threat alert as resolved."""
        if not self.conn:
            self.connect()
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE threat_alerts
                SET resolved = 1, resolved_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (alert_id,))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error resolving threat alert: {e}")
            raise

