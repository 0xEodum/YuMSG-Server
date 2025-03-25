from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from typing import Optional
import uvicorn
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.api.v1 import router as api_router
from app.api.v1.endpoints import auth, users
from app.api.v1.endpoints import websocket as ws_endpoints
from app.core.logging import logging_middleware
from app.database import init_db
from app.core.crypto import CryptoService
from app.models.user import User, UserDevice  # Явно импортируем модели

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
app.include_router(api_router.router)  # Используем router из api_router


# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(None)):
    from app.database import get_db
    db = next(get_db())
    await ws_endpoints.websocket_endpoint(websocket, token, db)


# Basic health check endpoint
@app.get("/")
async def health_check():
    return {"status": "ok", "message": "Server is running"}


# Создаем директорию для аватаров, если её нет
avatar_directory = Path("avatars")
avatar_directory.mkdir(exist_ok=True)


# Startup event
@app.on_event("startup")
async def startup_event():
    # Initialize database
    init_db()

    # Generate server keypair
    server_keys = crypto_service.generate_server_keypair()
    # В реальном приложении сохранить ключи в защищенном месте

    # Создаем аватар по умолчанию, если его нет
    default_avatar = avatar_directory / "default.png"
    if not default_avatar.exists():
        try:
            from PIL import Image
            img = Image.new('RGB', (200, 200), color=(73, 109, 137))
            img.save(default_avatar)
        except Exception as e:
            print(f"Error creating default avatar: {str(e)}")

    # Запускаем фоновые задачи
    from app.services.scheduled_tasks import start_background_tasks
    start_background_tasks()


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=3939, reload=True)