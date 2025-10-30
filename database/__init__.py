"""Database abstraction layer."""
from .base import DatabaseBase
from .postgresql import PostgreSQLDatabase
from .sqlite import SQLiteDatabase
import config

def get_database() -> DatabaseBase:
    """Factory function to get the appropriate database instance based on config."""
    db_type = config.config.database.type.lower()
    if db_type == "postgresql":
        return PostgreSQLDatabase()
    elif db_type == "sqlite":
        return SQLiteDatabase()
    else:
        raise ValueError(f"Unsupported database type: {db_type}")

__all__ = ["DatabaseBase", "PostgreSQLDatabase", "SQLiteDatabase", "get_database"]

