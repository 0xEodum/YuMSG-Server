from fastapi import APIRouter
from .endpoints import auth, users

router = APIRouter()

# Подключаем эндпоинты авторизации
router.include_router(auth.router, prefix="/auth", tags=["auth"])

# Подключаем эндпоинты пользователей
router.include_router(users.router, prefix="/users", tags=["users"])