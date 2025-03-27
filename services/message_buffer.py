"""
Модуль буфера сообщений на основе Redis.
Используется для временного хранения сообщений для пользователей, которые не в сети.
"""
import asyncio
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging
from ..core.redis_config import (
    RedisManager, KEY_PREFIX_MESSAGE_BUFFER,
    serialize_json, deserialize_json
)

# Настройка логирования
logger = logging.getLogger(__name__)


class MessageBuffer:
    """
    Буфер для хранения сообщений, предназначенных для оффлайн пользователей.
    Использует Redis для персистентного хранения сообщений.
    """

    def __init__(self, max_messages_per_user: int = 100, max_age_days: int = 7):
        """
        Инициализирует буфер сообщений.

        Args:
            max_messages_per_user: Максимальное количество сообщений для одного пользователя
            max_age_days: Максимальное время хранения сообщений в днях
        """
        self.max_messages_per_user = max_messages_per_user
        # Время жизни буфера сообщений пользователя в Redis (в секундах)
        self.message_ttl = max_age_days * 86400  # дни -> секунды

    async def add_message(self, user_id: str, message: Dict[str, Any]) -> bool:
        """
        Добавляет сообщение в буфер для конкретного пользователя.

        Args:
            user_id: ID пользователя-получателя
            message: Словарь с данными сообщения

        Returns:
            True, если сообщение успешно добавлено, иначе False
        """
        try:
            # Создаем ключ для списка сообщений пользователя
            user_key = f"{KEY_PREFIX_MESSAGE_BUFFER}{user_id}"

            # Добавляем временную метку для отслеживания возраста сообщения
            message_with_timestamp = {
                "message": message,
                "timestamp": datetime.utcnow().isoformat()
            }

            # Сериализуем сообщение
            message_data = serialize_json(message_with_timestamp)

            redis_client = await RedisManager.get_messages_redis()
            try:
                # Транзакция для атомарных операций с буфером сообщений
                tr = redis_client.pipeline()

                # Добавляем сообщение в начало списка Redis
                await tr.lpush(user_key, message_data)

                # Обрезаем список до максимального размера
                await tr.ltrim(user_key, 0, self.max_messages_per_user - 1)

                # Устанавливаем TTL для всего списка, если он еще не установлен
                await tr.expire(user_key, self.message_ttl)

                # Выполняем все команды атомарно
                await tr.execute()

                logger.debug(f"Message added to buffer for user {user_id}")
                return True

            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error adding message to buffer for user {user_id}: {str(e)}")
            return False

    async def get_messages(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Получает и удаляет все сообщения для пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            Список сообщений
        """
        try:
            user_key = f"{KEY_PREFIX_MESSAGE_BUFFER}{user_id}"

            redis_client = await RedisManager.get_messages_redis()
            try:
                # Атомарная операция: получаем все сообщения и удаляем список
                tr = redis_client.pipeline()
                await tr.lrange(user_key, 0, -1)  # Получаем все сообщения
                await tr.delete(user_key)  # Удаляем ключ
                results = await tr.execute()

                messages_data = results[0]  # Результат lrange

                if not messages_data:
                    return []

                # Десериализуем сообщения
                messages = []
                for message_data in messages_data:
                    try:
                        message_obj = deserialize_json(message_data)
                        if message_obj and "message" in message_obj:
                            messages.append(message_obj["message"])
                    except Exception as e:
                        logger.error(f"Error deserializing message: {str(e)}")

                logger.info(f"Retrieved and cleared {len(messages)} messages for user {user_id}")
                return messages

            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error getting messages for user {user_id}: {str(e)}")
            return []

    async def peek_messages(self, user_id: str, count: int = -1) -> List[Dict[str, Any]]:
        """
        Просматривает сообщения пользователя без их удаления.

        Args:
            user_id: ID пользователя
            count: Количество сообщений для просмотра (-1 для всех)

        Returns:
            Список сообщений
        """
        try:
            user_key = f"{KEY_PREFIX_MESSAGE_BUFFER}{user_id}"

            redis_client = await RedisManager.get_messages_redis()
            try:
                # Получаем сообщения без удаления
                messages_data = await redis_client.lrange(user_key, 0, count - 1 if count > 0 else -1)

                if not messages_data:
                    return []

                # Десериализуем сообщения
                messages = []
                for message_data in messages_data:
                    try:
                        message_obj = deserialize_json(message_data)
                        if message_obj and "message" in message_obj:
                            messages.append(message_obj["message"])
                    except Exception as e:
                        logger.error(f"Error deserializing message: {str(e)}")

                return messages

            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error peeking messages for user {user_id}: {str(e)}")
            return []

    async def count_messages(self, user_id: str) -> int:
        """
        Возвращает количество сообщений в буфере для пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            Количество сообщений
        """
        try:
            user_key = f"{KEY_PREFIX_MESSAGE_BUFFER}{user_id}"

            redis_client = await RedisManager.get_messages_redis()
            try:
                count = await redis_client.llen(user_key)
                return count
            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error counting messages for user {user_id}: {str(e)}")
            return 0

    async def remove_expired_messages(self, older_than_days: Optional[int] = None) -> int:
        """
        Ручное удаление устаревших сообщений.
        В большинстве случаев это не требуется, так как Redis автоматически удаляет ключи по TTL.

        Args:
            older_than_days: Удалить сообщения старше указанного количества дней

        Returns:
            Количество удаленных сообщений
        """
        # В нашей реализации с Redis это не нужно - ключи удаляются автоматически по TTL
        # Этот метод добавлен для совместимости с прежним API
        logger.debug("remove_expired_messages called, but not needed with Redis implementation")
        return 0

    async def clear_all_messages(self) -> int:
        """
        Удаляет все сообщения из буфера.
        Используется для тестирования или экстренной очистки.

        Returns:
            Количество удаленных ключей (буферов пользователей)
        """
        try:
            redis_client = await RedisManager.get_messages_redis()
            try:
                # Ищем все ключи с префиксом буфера сообщений
                pattern = f"{KEY_PREFIX_MESSAGE_BUFFER}*"
                cursor = 0
                deleted_count = 0

                while True:
                    cursor, keys = await redis_client.scan(cursor=cursor, match=pattern, count=100)
                    if keys:
                        result = await redis_client.delete(*keys)
                        deleted_count += result

                    if cursor == 0:
                        break

                logger.info(f"Cleared {deleted_count} message buffers from Redis")
                return deleted_count

            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error clearing all messages: {str(e)}")
            return 0


# Создаем глобальный экземпляр буфера сообщений
message_buffer = MessageBuffer()