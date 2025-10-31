"""User management routes."""
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from api.models import UserResponse, UserCreate, UserUpdate
from api.auth import get_current_active_user, require_admin, get_password_hash
from api.dependencies import get_db
from database.base import DatabaseBase

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=List[UserResponse])
async def get_users(
    skip: int = 0,
    limit: int = 100,
    current_user: dict = Depends(require_admin),
    db: DatabaseBase = Depends(get_db)
):
    """Get all users (admin only)."""
    users = db.get_all_users(skip=skip, limit=limit)
    # Remove passwords from response
    return [UserResponse(**{k: v for k, v in user.items() if k != "hashed_password"}) for user in users]


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user: dict = Depends(require_admin),
    db: DatabaseBase = Depends(get_db)
):
    """Get a specific user by ID (admin only)."""
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return UserResponse(**{k: v for k, v in user.items() if k != "hashed_password"})


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    current_user: dict = Depends(require_admin),
    db: DatabaseBase = Depends(get_db)
):
    """Create a new user (admin only)."""
    existing_user = db.get_user_by_username(user_data.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    hashed_password = get_password_hash(user_data.password)
    try:
        user_id = db.create_user(
            username=user_data.username,
            email=user_data.email,
            hashed_password=hashed_password,
            is_admin=user_data.is_admin,
            is_active=True
        )
        user = db.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )
        return UserResponse(**{k: v for k, v in user.items() if k != "hashed_password"})
    except Exception as e:
        if "UNIQUE constraint" in str(e) or "duplicate key" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already exists"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user: {str(e)}"
        )


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_user: dict = Depends(require_admin),
    db: DatabaseBase = Depends(get_db)
):
    """Update a user (admin only)."""
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prepare update data
    update_data = {}
    if user_data.username is not None:
        # Check if username is already taken by another user
        existing = db.get_user_by_username(user_data.username)
        if existing and existing["id"] != user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken"
            )
        update_data["username"] = user_data.username
    if user_data.email is not None:
        update_data["email"] = user_data.email
    if user_data.password is not None:
        update_data["hashed_password"] = get_password_hash(user_data.password)
    if user_data.is_admin is not None:
        update_data["is_admin"] = user_data.is_admin
    if user_data.is_active is not None:
        update_data["is_active"] = user_data.is_active
    
    if not update_data:
        # Return existing user if no updates
        return UserResponse(**{k: v for k, v in user.items() if k != "hashed_password"})
    
    # Update user
    success = db.update_user(user_id, **update_data)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user"
        )
    
    updated_user = db.get_user_by_id(user_id)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve updated user"
        )
    
    return UserResponse(**{k: v for k, v in updated_user.items() if k != "hashed_password"})


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    current_user: dict = Depends(require_admin),
    db: DatabaseBase = Depends(get_db)
):
    """Delete a user (admin only)."""
    # Prevent self-deletion
    if current_user["id"] == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    success = db.delete_user(user_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )
    return None

