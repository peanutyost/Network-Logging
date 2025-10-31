"""Authentication routes."""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from api.auth import (
    verify_password,
    get_password_hash,
    create_access_token,
    get_current_active_user,
    require_admin,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from api.models import Token, UserLogin, UserCreate, UserResponse, PasswordChange
from api.dependencies import get_db
from database.base import DatabaseBase

router = APIRouter(prefix="/api/auth", tags=["authentication"])


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: DatabaseBase = Depends(get_db)
):
    """Login endpoint."""
    import logging
    logger = logging.getLogger(__name__)
    
    user = db.get_user_by_username(form_data.username)
    if not user:
        logger.warning(f"Login attempt for non-existent user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check password
    password_valid = verify_password(form_data.password, user["hashed_password"])
    if not password_valid:
        logger.warning(f"Invalid password for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    db: DatabaseBase = Depends(get_db)
):
    """Register a new user."""
    # Check if username already exists
    existing_user = db.get_user_by_username(user_data.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Check if email already exists
    # Note: We'll need to add get_user_by_email method or check in create_user
    # For now, we'll let the database handle unique constraint
    
    hashed_password = get_password_hash(user_data.password)
    # Debug: Verify the hash immediately
    import logging
    logger = logging.getLogger(__name__)
    test_verify = verify_password(user_data.password, hashed_password)
    logger.debug(f"Password hash created for user {user_data.username}, verification test: {test_verify}")
    
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
        
        # Debug: Verify password against what was stored
        stored_hash = user.get("hashed_password")
        verify_stored = verify_password(user_data.password, stored_hash)
        logger.debug(f"Password verification against stored hash: {verify_stored}")
        if not verify_stored:
            logger.error(f"Password hash mismatch! Created hash: {hashed_password[:20]}..., Stored hash: {stored_hash[:20] if stored_hash else None}...")
        
        return UserResponse(**user)
    except Exception as e:
        # Check for unique constraint violation
        if "UNIQUE constraint" in str(e) or "duplicate key" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already exists"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user: {str(e)}"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_active_user)):
    """Get current user information."""
    # Remove password from response
    user_data = {k: v for k, v in current_user.items() if k != "hashed_password"}
    return UserResponse(**user_data)


@router.post("/change-password", response_model=UserResponse)
async def change_password(
    password_data: PasswordChange,
    current_user: dict = Depends(get_current_active_user),
    db: DatabaseBase = Depends(get_db)
):
    """Change current user's password."""
    # Verify current password
    if not verify_password(password_data.current_password, current_user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Hash new password
    new_hashed_password = get_password_hash(password_data.new_password)
    
    # Update password
    success = db.update_user(
        current_user["id"],
        hashed_password=new_hashed_password
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password"
        )
    
    # Get updated user
    updated_user = db.get_user_by_id(current_user["id"])
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve updated user"
        )
    
    return UserResponse(**{k: v for k, v in updated_user.items() if k != "hashed_password"})

