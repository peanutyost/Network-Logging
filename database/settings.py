"""Application settings storage."""
import json
import logging
from typing import Optional, Any, Dict
from database.base import DatabaseBase

logger = logging.getLogger(__name__)


class SettingsManager:
    """Manages application settings stored in database."""
    
    def __init__(self, db: DatabaseBase):
        """Initialize settings manager.
        
        Args:
            db: Database instance
        """
        self.db = db
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a setting value.
        
        Args:
            key: Setting key
            default: Default value if setting doesn't exist
            
        Returns:
            Setting value or default
        """
        return self.db.get_setting(key, default)
    
    def set_setting(self, key: str, value: Any) -> None:
        """Set a setting value.
        
        Args:
            key: Setting key
            value: Setting value (will be JSON encoded if not string/int)
        """
        self.db.set_setting(key, value)

