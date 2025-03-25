from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import secrets
from sqlalchemy.orm import Session
from ..database import get_db
from ..models.user import User

# Настройки JWT
SECRET_KEY = "your-secret-key"  # В продакшене должен быть в .env
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Создает JWT-токен доступа с ID пользователя в стандартном поле 'sub'.

    Args:
        data: Словарь с данными пользователя, должен содержать 'user_id' или 'sub'
        expires_delta: Опциональное время жизни токена

    Returns:
        Сгенерированный JWT-токен
    """
    to_encode = data.copy()

    # Если есть user_id, но нет sub, копируем значение
    if 'user_id' in to_encode and 'sub' not in to_encode:
        to_encode["sub"] = str(to_encode["user_id"])
        # Можно удалить user_id, чтобы избежать дублирования
        # del to_encode["user_id"]

    # Если нет ни user_id, ни sub, возбуждаем исключение
    if 'sub' not in to_encode:
        print(f"Warning: Missing 'sub' in token data: {to_encode}")

    # Добавляем время истечения
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    try:
        # Создаем токен
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        print(f"Error creating JWT: {str(e)}")
        import traceback
        print(traceback.format_exc())
        raise


def create_refresh_token():
    return secrets.token_urlsafe(32)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str):
    return pwd_context.hash(password)


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Проверяет и декодирует JWT токен, возвращая данные текущего пользователя.
    Если токен недействителен или пользователь не существует, выбрасывает исключение.
    """
    if token is None:
        print("No token provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        print(f"Decoding token: {token[:15]}...")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            print("No sub claim in token payload")
            raise credentials_exception

        print(f"Token decoded successfully for user_id: {user_id}")
    except JWTError as e:
        print(f"JWT decoding error: {str(e)}")
        raise credentials_exception

    try:
        # Проверяем существование и активность пользователя в базе
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            print(f"User with ID {user_id} not found in database")
            raise credentials_exception

        if not user.is_active:
            print(f"User with ID {user_id} is inactive")
            raise credentials_exception

        print(f"User {user.username} (ID: {user.id}) authenticated successfully")
    except Exception as e:
        print(f"Database error in get_current_user: {str(e)}")
        raise credentials_exception

    # Возвращаем данные из токена для использования в эндпоинтах
    return payload