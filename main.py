from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from typing import Optional
import uvicorn

from app.api.v1.endpoints import auth
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
app.include_router(auth.router, prefix="/auth", tags=["auth"])


# Basic health check endpoint
@app.get("/")
async def health_check():
    return {"status": "ok", "message": "Server is running"}


# Startup event
@app.on_event("startup")
async def startup_event():
    # Initialize database
    init_db()

    # Generate server keypair
    server_keys = crypto_service.generate_server_keypair()
    # В реальном приложении сохранить ключи в защищенном месте


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=3939, reload=True)