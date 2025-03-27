"""
Модуль сервиса онлайн-статусов пользователей на основе Redis.
Отслеживает, кто из пользователей в сети, используя временные метки активности.
"""
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional
import logging
from ..core.redis_config import RedisManager, KEY_PREFIX_ONLINE, serialize_json, deserialize_json

# Настройка логирования
logger = logging.getLogger(__name__)


class OnlineStatusService:
    """
    Сервис для отслеживания онлайн-статуса пользователей.
    Использует Redis для хранения состояния с автоматическим истечением.
    """

    def __init__(self, activity_timeout_minutes: int = 5):
        """
        Инициализирует сервис отслеживания онлайн-статуса.

        Args:
            activity_timeout_minutes: Время в минутах, после которого пользователь считается оффлайн
        """
        self.activity_timeout_seconds = activity_timeout_minutes * 60

    async def set_user_online(self, user_id: str) -> bool:
        """
        Устанавливает статус пользователя как 'онлайн'.

        Args:
            user_id: ID пользователя

        Returns:
            True, если операция успешна, иначе False
        """
        try:
            key = f"{KEY_PREFIX_ONLINE}{user_id}"
            status_data = serialize_json({
                "last_active": datetime.utcnow().isoformat(),
                "status": "online"
            })

            redis_client = await RedisManager.get_status_redis()
            try:
                # Сохраняем статус с TTL
                await redis_client.setex(
                    key,
                    self.activity_timeout_seconds,
                    status_data
                )
                logger.debug(f"User {user_id} set as online, TTL: {self.activity_timeout_seconds}s")
                return True
            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error setting user {user_id} online: {str(e)}")
            return False

    async def set_user_offline(self, user_id: str) -> bool:
        """
        Устанавливает статус пользователя как 'оффлайн'.

        Args:
            user_id: ID пользователя

        Returns:
            True, если операция успешна, иначе False
        """
        try:
            key = f"{KEY_PREFIX_ONLINE}{user_id}"

            redis_client = await RedisManager.get_status_redis()
            try:
                # Проверяем, есть ли запись
                if await redis_client.exists(key):
                    # Устанавливаем статус offline, но сохраняем время последней активности
                    # и оставляем ключ на короткое время для уведомления других клиентов
                    current_data = await redis_client.get(key)

                    if current_data:
                        try:
                            data = deserialize_json(current_data)
                            data["status"] = "offline"

                            # Сохраняем с TTL в 60 секунд, чтобы клиенты могли получить обновление
                            await redis_client.setex(
                                key,
                                60,  # 1 минута для получения обновления
                                serialize_json(data)
                            )
                            logger.debug(f"User {user_id} set as offline with 60s TTL")
                            return True
                        except Exception as e:
                            logger.error(f"Error processing status data: {str(e)}")

                # Если записи нет или возникла ошибка, просто удаляем ключ
                await redis_client.delete(key)
                logger.debug(f"User {user_id} status key deleted")
                return True

            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error setting user {user_id} offline: {str(e)}")
            return False

    async def is_user_online(self, user_id: str) -> bool:
        """
        Проверяет, онлайн ли пользователь.

        Args:
            user_id: ID пользователя

        Returns:
            True, если пользователь онлайн, иначе False
        """
        try:
            key = f"{KEY_PREFIX_ONLINE}{user_id}"

            redis_client = await RedisManager.get_status_redis()
            try:
                # Проверяем наличие ключа и его статус
                data = await redis_client.get(key)

                if not data:
                    return False

                try:
                    status_data = deserialize_json(data)
                    if status_data.get("status") == "offline":
                        return False

                    # Если статус не указан или "online", считаем пользователя онлайн
                    return True
                except Exception as e:
                    logger.error(f"Error parsing status data: {str(e)}")
                    return False

            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error checking if user {user_id} is online: {str(e)}")
            return False

    async def get_online_users(self) -> List[str]:
        """
        Получает список ID всех онлайн пользователей.

        Returns:
            Список ID пользователей
        """
        try:
            pattern = f"{KEY_PREFIX_ONLINE}*"

            redis_client = await RedisManager.get_status_redis()
            try:
                cursor = 0
                online_users = []

                while True:
                    cursor, keys = await redis_client.scan(cursor=cursor, match=pattern, count=100)

                    # Проверяем каждый ключ
                    for key in keys:
                        try:
                            # Извлекаем user_id из ключа
                            user_id = key.decode('utf-8').replace(KEY_PREFIX_ONLINE, '')

                            # Проверяем статус
                            data = await redis_client.get(key)
                            if data:
                                status_data = deserialize_json(data)
                                if status_data.get("status") != "offline":
                                    online_users.append(user_id)
                        except Exception as e:
                            logger.error(f"Error processing key {key}: {str(e)}")

                    if cursor == 0:
                        break

                return online_users

            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error getting online users: {str(e)}")
            return []

    async def get_user_last_activity(self, user_id: str) -> Optional[datetime]:
        """
        Получает время последней активности пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            Время последней активности или None, если информация недоступна
        """
        try:
            key = f"{KEY_PREFIX_ONLINE}{user_id}"

            redis_client = await RedisManager.get_status_redis()
            try:
                data = await redis_client.get(key)

                if not data:
                    return None

                status_data = deserialize_json(data)
                last_active_str = status_data.get("last_active")

                if not last_active_str:
                    return None

                return datetime.fromisoformat(last_active_str)

            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error getting last activity for user {user_id}: {str(e)}")
            return None

    async def clear_all_statuses(self) -> int:
        """
        Удаляет все статусы из Redis.
        Используется для тестирования или экстренной очистки.

        Returns:
            Количество удаленных записей
        """
        try:
            redis_client = await RedisManager.get_status_redis()
            try:
                pattern = f"{KEY_PREFIX_ONLINE}*"
                cursor = 0
                deleted_count = 0

                while True:
                    cursor, keys = await redis_client.scan(cursor=cursor, match=pattern, count=100)
                    if keys:
                        result = await redis_client.delete(*keys)
                        deleted_count += result

                    if cursor == 0:
                        break

                logger.info(f"Cleared {deleted_count} online statuses from Redis")
                return deleted_count

            finally:
                await redis_client.close()

        except Exception as e:
            logger.error(f"Error clearing all statuses: {str(e)}")
            return 0


# Создаем глобальный экземпляр сервиса
online_status_service = OnlineStatusService()