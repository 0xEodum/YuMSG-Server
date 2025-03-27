"""
Модуль конфигурации Redis для приложения.
Предоставляет функции и классы для работы с Redis.
"""
import os
from typing import Optional, Any, Dict
import json
import pickle
from datetime import datetime
import redis.asyncio as redis_async
from fastapi import Depends
from functools import lru_cache

# Параметры подключения к Redis из переменных окружения или значения по умолчанию
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
REDIS_DB_CHANNELS = int(os.getenv("REDIS_DB_CHANNELS", 0))  # Защищенные каналы
REDIS_DB_MESSAGES = int(os.getenv("REDIS_DB_MESSAGES", 1))  # Буфер сообщений
REDIS_DB_STATUS = int(os.getenv("REDIS_DB_STATUS", 2))  # Статусы онлайн
REDIS_DB_SESSIONS = int(os.getenv("REDIS_DB_SESSIONS", 3))  # Сессии пользователей

# Префиксы ключей для Redis
KEY_PREFIX_CHANNEL = "channel:"
KEY_PREFIX_MESSAGE_BUFFER = "message_buffer:"
KEY_PREFIX_ONLINE = "online:"
KEY_PREFIX_SESSION = "session:"


class RedisManager:
    """
    Менеджер для работы с Redis.
    Предоставляет методы для получения соединений с разными базами Redis.
    """
    _pools: Dict[int, redis_async.ConnectionPool] = {}

    @classmethod
    async def get_pool(cls, db: int) -> redis_async.ConnectionPool:
        """
        Получает или создает пул соединений с Redis для указанной БД.
        """
        if db not in cls._pools:
            cls._pools[db] = redis_async.ConnectionPool(
                host=REDIS_HOST,
                port=REDIS_PORT,
                password=REDIS_PASSWORD,
                db=db,
                decode_responses=False,  # Не декодируем автоматически для поддержки бинарных данных
                max_connections=20,  # Ограничение числа соединений
                health_check_interval=30  # Проверка состояния соединений
            )
        return cls._pools[db]

    @classmethod
    async def get_redis(cls, db: int) -> redis_async.Redis:
        """
        Получает клиент Redis для указанной БД.
        """
        pool = await cls.get_pool(db)
        return redis_async.Redis(connection_pool=pool)

    @classmethod
    async def get_channels_redis(cls) -> redis_async.Redis:
        """
        Получает клиент Redis для работы с защищенными каналами.
        """
        return await cls.get_redis(REDIS_DB_CHANNELS)

    @classmethod
    async def get_messages_redis(cls) -> redis_async.Redis:
        """
        Получает клиент Redis для работы с буфером сообщений.
        """
        return await cls.get_redis(REDIS_DB_MESSAGES)

    @classmethod
    async def get_status_redis(cls) -> redis_async.Redis:
        """
        Получает клиент Redis для работы со статусами онлайн.
        """
        return await cls.get_redis(REDIS_DB_STATUS)

    @classmethod
    async def get_sessions_redis(cls) -> redis_async.Redis:
        """
        Получает клиент Redis для работы с сессиями пользователей.
        """
        return await cls.get_redis(REDIS_DB_SESSIONS)

    @classmethod
    async def close_all_pools(cls):
        """
        Закрывает все пулы соединений.
        """
        for pool in cls._pools.values():
            await pool.disconnect()
        cls._pools.clear()


# Зависимости для FastAPI
async def get_channels_redis_dependency() -> redis_async.Redis:
    """Зависимость FastAPI для Redis защищенных каналов"""
    redis_client = await RedisManager.get_channels_redis()
    try:
        yield redis_client
    finally:
        await redis_client.close()


async def get_messages_redis_dependency() -> redis_async.Redis:
    """Зависимость FastAPI для Redis буфера сообщений"""
    redis_client = await RedisManager.get_messages_redis()
    try:
        yield redis_client
    finally:
        await redis_client.close()


async def get_status_redis_dependency() -> redis_async.Redis:
    """Зависимость FastAPI для Redis статусов онлайн"""
    redis_client = await RedisManager.get_status_redis()
    try:
        yield redis_client
    finally:
        await redis_client.close()


async def get_sessions_redis_dependency() -> redis_async.Redis:
    """Зависимость FastAPI для Redis сессий"""
    redis_client = await RedisManager.get_sessions_redis()
    try:
        yield redis_client
    finally:
        await redis_client.close()


# Утилиты для сериализации и десериализации данных
def serialize_json(data: Any) -> bytes:
    """Сериализует данные в JSON и возвращает байты"""
    return json.dumps(data).encode('utf-8')


def deserialize_json(data: bytes) -> Any:
    """Десериализует JSON из байтов"""
    if data is None:
        return None
    return json.loads(data.decode('utf-8'))


def serialize_pickle(data: Any) -> bytes:
    """Сериализует данные с помощью pickle"""
    return pickle.dumps(data)


def deserialize_pickle(data: bytes) -> Any:
    """Десериализует данные из pickle"""
    if data is None:
        return None
    return pickle.loads(data)


# События для FastAPI
async def startup_redis():
    """Событие запуска приложения FastAPI"""
    # Предварительно инициализируем пулы для быстрого старта
    await RedisManager.get_channels_redis()
    await RedisManager.get_messages_redis()
    await RedisManager.get_status_redis()
    await RedisManager.get_sessions_redis()


async def shutdown_redis():
    """Событие остановки приложения FastAPI"""
    await RedisManager.close_all_pools()