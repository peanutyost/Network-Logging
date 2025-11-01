#!/usr/bin/env python3
"""Script to make a user an admin."""
import sys
import os
from database import get_database

def make_user_admin(username: str):
    """Make a user an admin."""
    db = get_database()
    db.connect()
    
    try:
        # Get user
        user = db.get_user_by_username(username)
        if not user:
            print(f"Error: User '{username}' not found")
            return False
        
        # Check if already admin
        if user.get('is_admin'):
            print(f"User '{username}' is already an admin")
            return True
        
        # Update to admin
        success = db.update_user(user['id'], is_admin=True)
        if success:
            print(f"Successfully made user '{username}' an admin")
            return True
        else:
            print(f"Error: Failed to update user '{username}'")
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        db.disconnect()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py <username>")
        sys.exit(1)
    
    username = sys.argv[1]
    success = make_user_admin(username)
    sys.exit(0 if success else 1)

