"""
Сервис защищенных каналов с использованием Redis.
Управляет созданием, хранением и удалением защищенных каналов для обмена зашифрованными данными.
"""
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import traceback
import logging
from ..core.redis_config import (
    RedisManager, KEY_PREFIX_CHANNEL,
    serialize_pickle, deserialize_pickle
)
from ..core.crypto import CryptoService

# Настройка логирования
logger = logging.getLogger(__name__)


class SecureChannel:
    """
    Модель защищенного канала связи.
    Хранит идентификатор канала, публичный ключ клиента и сессионный ключ.
    """

    def __init__(self, channel_id: str, public_key: str, session_key: bytes):
        self.channel_id = channel_id
        self.public_key = public_key
        self.session_key = session_key
        self.created_at = datetime.utcnow()
        # Время жизни канала - 30 минут
        self.expires_at = self.created_at + timedelta(minutes=30)

    @property
    def is_expired(self) -> bool:
        """Проверяет, истек ли срок действия канала"""
        now = datetime.utcnow()
        is_expired = now > self.expires_at
        time_left = self.expires_at - now if not is_expired else timedelta(0)
        logger.debug(f"Channel {self.channel_id} expired: {is_expired}, time left: {time_left}")
        return is_expired

    def to_dict(self) -> dict:
        """Преобразует канал в словарь для сериализации"""
        return {
            "channel_id": self.channel_id,
            "public_key": self.public_key,
            "session_key": self.session_key,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat()
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'SecureChannel':
        """Создает экземпляр канала из словаря"""
        channel = cls(
            channel_id=data["channel_id"],
            public_key=data["public_key"],
            session_key=data["session_key"]
        )
        channel.created_at = datetime.fromisoformat(data["created_at"])
        channel.expires_at = datetime.fromisoformat(data["expires_at"])
        return channel


class SecureChannelService:
    """
    Сервис для управления защищенными каналами связи с использованием Redis.
    Обеспечивает создание, хранение и использование каналов для шифрования данных.
    """

    def __init__(self, crypto_service: CryptoService):
        self._crypto_service = crypto_service
        # Время жизни канала в Redis (в секундах) - 30 минут
        self._channel_ttl = 1800

    async def create_channel(self, channel_id: str, client_public_key: str) -> str:
        """
        Создает новый защищенный канал и возвращает зашифрованный сессионный ключ.

        Args:
            channel_id: Уникальный идентификатор канала
            client_public_key: Публичный ключ клиента в формате JSON

        Returns:
            Зашифрованный сессионный ключ в формате base64
        """
        try:
            logger.info(f"Creating channel with ID: {channel_id}")

            # Генерируем сессионный ключ
            session_key = self._crypto_service.generate_session_key()
            logger.debug(f"Generated session key length: {len(session_key)} bytes")

            # Создаем канал
            channel = SecureChannel(
                channel_id=channel_id,
                public_key=client_public_key,
                session_key=session_key
            )

            # Сериализуем канал и сохраняем в Redis с TTL
            redis_client = await RedisManager.get_channels_redis()
            try:
                serialized_channel = serialize_pickle(channel)
                key = f"{KEY_PREFIX_CHANNEL}{channel_id}"

                # Сохраняем канал с временем жизни
                await redis_client.setex(key, self._channel_ttl, serialized_channel)
                logger.info(f"Channel {channel_id} saved to Redis with TTL {self._channel_ttl} seconds")
            finally:
                await redis_client.close()

            # Шифруем сессионный ключ публичным ключом клиента
            logger.debug("Attempting to encrypt session key...")
            encrypted_key = self._crypto_service.encrypt_session_key(
                session_key,
                client_public_key
            )
            logger.debug(f"Session key encrypted. Encrypted length: {len(encrypted_key)}")

            return encrypted_key

        except Exception as e:
            logger.error(f"Error in create_channel: {str(e)}")
            logger.error(f"Error type: {type(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    async def get_channel(self, channel_id: str) -> Optional[SecureChannel]:
        """
        Получает канал по ID и проверяет его валидность.

        Args:
            channel_id: Идентификатор канала

        Returns:
            Объект канала или None, если канал не найден или истек срок его действия
        """
        logger.debug(f"Looking for channel: {channel_id}")

        try:
            # Получаем канал из Redis
            redis_client = await RedisManager.get_channels_redis()
            try:
                key = f"{KEY_PREFIX_CHANNEL}{channel_id}"
                serialized_channel = await redis_client.get(key)

                if not serialized_channel:
                    logger.debug(f"Channel {channel_id} not found in Redis")
                    return None

                # Десериализуем канал
                channel = deserialize_pickle(serialized_channel)
                logger.debug(f"Channel {channel_id} found in Redis")

                # Проверяем, не истек ли срок действия канала
                if channel.is_expired:
                    logger.info(f"Channel {channel_id} is expired")
                    await self.remove_channel(channel_id)
                    return None

                return channel

            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error getting channel {channel_id}: {str(e)}")
            logger.error(traceback.format_exc())
            return None

    async def decrypt_data(self, channel_id: str, encrypted_data: str) -> str:
        """
        Расшифровывает данные с помощью сессионного ключа канала.

        Args:
            channel_id: Идентификатор канала
            encrypted_data: Зашифрованные данные в формате base64

        Returns:
            Расшифрованные данные

        Raises:
            ValueError: Если канал не найден или истек срок его действия
        """
        logger.debug(f"Attempting to decrypt data for channel {channel_id}")

        channel = await self.get_channel(channel_id)
        if not channel:
            logger.error(f"Channel {channel_id} not found or expired")
            raise ValueError("Invalid or expired channel")

        logger.debug(f"Channel found, session key length: {len(channel.session_key)}")

        try:
            decrypted = self._crypto_service.decrypt_with_session_key(
                encrypted_data,
                channel.session_key
            )
            logger.debug(f"Decryption successful. Result length: {len(decrypted)}")
            return decrypted
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            logger.error(traceback.format_exc())
            raise

    async def encrypt_data(self, channel_id: str, data: str) -> str:
        """
        Шифрует данные с помощью сессионного ключа канала.

        Args:
            channel_id: Идентификатор канала
            data: Данные для шифрования

        Returns:
            Зашифрованные данные в формате base64

        Raises:
            ValueError: Если канал не найден или истек срок его действия
        """
        channel = await self.get_channel(channel_id)
        if not channel:
            raise ValueError("Invalid or expired channel")

        return self._crypto_service.encrypt_with_session_key(
            data,
            channel.session_key
        )

    async def remove_channel(self, channel_id: str) -> bool:
        """
        Удаляет канал из Redis.

        Args:
            channel_id: Идентификатор канала

        Returns:
            True, если канал был удален, иначе False
        """
        try:
            redis_client = await RedisManager.get_channels_redis()
            try:
                key = f"{KEY_PREFIX_CHANNEL}{channel_id}"
                result = await redis_client.delete(key)
                success = result > 0

                if success:
                    logger.info(f"Channel {channel_id} removed from Redis")
                else:
                    logger.debug(f"Channel {channel_id} not found in Redis for removal")

                return success
            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error removing channel {channel_id}: {str(e)}")
            return False

    async def clear_all_channels(self) -> int:
        """
        Удаляет все каналы из Redis.
        Используется для тестирования и в крайних случаях.

        Returns:
            Количество удаленных каналов
        """
        try:
            redis_client = await RedisManager.get_channels_redis()
            try:
                # Ищем все ключи с префиксом для каналов
                pattern = f"{KEY_PREFIX_CHANNEL}*"
                cursor = 0
                deleted_count = 0

                while True:
                    cursor, keys = await redis_client.scan(cursor=cursor, match=pattern, count=100)
                    if keys:
                        result = await redis_client.delete(*keys)
                        deleted_count += result

                    if cursor == 0:
                        break

                logger.info(f"Cleared {deleted_count} channels from Redis")
                return deleted_count
            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error clearing channels: {str(e)}")
            return 0


# Создаем глобальный экземпляр сервиса
from ..core.crypto import CryptoService

crypto_service = CryptoService()
secure_channel_service = SecureChannelService(crypto_service)