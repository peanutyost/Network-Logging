"""Configuration module for network traffic DNS logger."""
import os
from typing import List, Optional
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


@dataclass
class DatabaseConfig:
    """Database configuration."""
    type: str = "postgresql"  # postgresql, sqlite
    host: str = "localhost"
    port: int = 5432
    name: str = "network_logging"
    user: str = "postgres"
    password: str = "postgres"
    
    @classmethod
    def from_env(cls) -> "DatabaseConfig":
        """Load database config from environment variables."""
        return cls(
            type=os.getenv("DB_TYPE", "postgresql"),
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432")),
            name=os.getenv("DB_NAME", "network_logging"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "postgres"),
        )
    
    def get_connection_string(self) -> str:
        """Get database connection string."""
        if self.type == "postgresql":
            return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"
        elif self.type == "sqlite":
            return f"sqlite:///{self.name}.db"
        else:
            raise ValueError(f"Unsupported database type: {self.type}")


@dataclass
class CaptureConfig:
    """Packet capture configuration."""
    ports: List[int] = None  # None means capture all traffic
    interface: Optional[str] = None  # None means use default interface
    bpf_filter: Optional[str] = None  # Optional BPF filter
    snapshot_length: int = 65535  # Maximum bytes to capture per packet
    timeout: int = 1  # Timeout in seconds
    
    @classmethod
    def from_env(cls) -> "CaptureConfig":
        """Load capture config from environment variables."""
        ports_str = os.getenv("CAPTURE_PORTS", "")
        ports = [int(p) for p in ports_str.split(",") if p.strip()] if ports_str else None
        
        return cls(
            ports=ports,
            interface=os.getenv("CAPTURE_INTERFACE"),
            bpf_filter=os.getenv("CAPTURE_BPF_FILTER"),
            snapshot_length=int(os.getenv("CAPTURE_SNAPSHOT_LENGTH", "65535")),
            timeout=int(os.getenv("CAPTURE_TIMEOUT", "1")),
        )


@dataclass
class AppConfig:
    """Application configuration."""
    database: DatabaseConfig = None
    capture: CaptureConfig = None
    log_level: str = "INFO"
    orphaned_ip_days: int = 7  # Days to look back for DNS match
    
    @classmethod
    def from_env(cls) -> "AppConfig":
        """Load full config from environment variables."""
        return cls(
            database=DatabaseConfig.from_env(),
            capture=CaptureConfig.from_env(),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            orphaned_ip_days=int(os.getenv("ORPHANED_IP_DAYS", "7")),
        )


# Global config instance
config = AppConfig.from_env()

