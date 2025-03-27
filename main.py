from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from typing import Optional
import uvicorn
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import logging

from app.api.v1 import router as api_router
from app.api.v1.endpoints import auth, users
from app.api.v1.endpoints import websocket as ws_endpoints
from app.core.logging import logging_middleware
from app.database import init_db
from app.core.crypto import CryptoService
from app.models.user import User, UserDevice  # Явно импортируем модели
from app.core.redis_config import startup_redis, shutdown_redis

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('server.log')
    ]
)
logger = logging.getLogger(__name__)

# Создаем приложение FastAPI
app = FastAPI(title="Chat Server API")

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add logging middleware
app.middleware("http")(logging_middleware)

# Initialize crypto service
crypto_service = CryptoService()

# Include routers
app.include_router(api_router.router)


# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(None)):
    from app.database import get_db
    db = next(get_db())
    try:
        await ws_endpoints.websocket_endpoint(websocket, token, db)
    except Exception as e:
        logger.error(f"Error in websocket_endpoint: {str(e)}")
        if websocket.client_state.CONNECTED:
            await websocket.close(code=1011, reason="Internal server error")


# Basic health check endpoint
@app.get("/")
async def health_check():
    return {"status": "ok", "message": "Server is running"}


# Создаем директорию для аватаров, если её нет
avatar_directory = Path("avatars")
avatar_directory.mkdir(exist_ok=True)


# События FastAPI
@app.on_event("startup")
async def startup_event():
    logger.info("Starting up server...")

    # Инициализируем Redis
    await startup_redis()
    logger.info("Redis initialized")

    # Инициализируем базу данных
    init_db()
    logger.info("Database initialized")

    # Генерируем серверный ключ шифрования
    server_keys = crypto_service.generate_server_keypair()
    logger.info("Server key pair generated")

    # Создаем аватар по умолчанию, если его нет
    default_avatar = avatar_directory / "default.png"
    if not default_avatar.exists():
        try:
            from PIL import Image
            img = Image.new('RGB', (200, 200), color=(73, 109, 137))
            img.save(default_avatar)
            logger.info("Default avatar created")
        except Exception as e:
            logger.error(f"Error creating default avatar: {str(e)}")

    logger.info("Server startup completed successfully")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down server...")

    # Закрываем соединения с Redis
    await shutdown_redis()
    logger.info("Redis connections closed")

    logger.info("Server shutdown completed")


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=3939,
        reload=True,
        log_level="info"
    )