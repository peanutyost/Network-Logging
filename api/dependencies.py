"""FastAPI dependencies."""
from database import get_database
from database.base import DatabaseBase

_db_instance = None

def get_db() -> DatabaseBase:
    """Dependency to get database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = get_database()
        _db_instance.connect()
    return _db_instance
