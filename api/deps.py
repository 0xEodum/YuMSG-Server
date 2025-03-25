"""
Зависимости для FastAPI эндпоинтов
"""
from fastapi import Depends
from ..services.secure_channel_service import secure_channel_service
from ..core.crypto import CryptoService

def get_secure_channel_service():
    """
    Зависимость для получения сервиса защищенных каналов.
    Используется для гарантии использования одного экземпляра сервиса во всех запросах.
    """
    return secure_channel_service

def get_crypto_service():
    """
    Зависимость для получения сервиса криптографии.
    """
    return CryptoService()