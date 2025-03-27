"""
Модуль управления WebSocket соединениями.
Обеспечивает отслеживание активных соединений и отправку сообщений.
"""
import asyncio
import json
from typing import Dict, Optional, Set, List, Any
import logging
from fastapi import WebSocket
from datetime import datetime, timedelta

from .online_status_service import online_status_service
from .message_buffer import message_buffer
from ..core.redis_config import (
    RedisManager, KEY_PREFIX_ONLINE,
    serialize_json, deserialize_json
)

# Настройка логирования
logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Менеджер WebSocket соединений пользователей.
    Хранит и управляет активными соединениями.
    """

    def __init__(self):
        # Словарь user_id -> WebSocket для активных соединений в текущем экземпляре сервера
        # Это локальная структура данных, не синхронизируемая между серверами через Redis,
        # так как WebSocket соединения не могут быть сериализованы или переданы другим серверам
        self.active_connections: Dict[str, WebSocket] = {}

        # Уникальный ID сервера для кластерной работы
        import uuid
        import os
        self.server_id = os.getenv("SERVER_ID", str(uuid.uuid4()))
        logger.info(f"ConnectionManager initialized with server_id: {self.server_id}")

    async def connect(self, user_id: str, websocket: WebSocket) -> bool:
        """
        Устанавливает соединение и добавляет его в список активных.

        Args:
            user_id: ID пользователя
            websocket: Объект WebSocket соединения

        Returns:
            True, если соединение установлено успешно
        """
        try:
            # Принимаем соединение
            await websocket.accept()

            # Добавляем в локальный словарь
            self.active_connections[user_id] = websocket

            # Обновляем статус пользователя в Redis
            await online_status_service.set_user_online(user_id)

            # Публикуем событие подключения в Redis Pub/Sub для других серверов
            await self._publish_user_event(user_id, "connect")

            logger.info(f"User {user_id} connected to server {self.server_id}")
            return True

        except Exception as e:
            logger.error(f"Error connecting user {user_id}: {str(e)}")
            return False

    async def disconnect(self, user_id: str) -> bool:
        """
        Удаляет соединение из списка активных.

        Args:
            user_id: ID пользователя

        Returns:
            True, если операция успешна
        """
        try:
            # Удаляем из локального словаря
            if user_id in self.active_connections:
                del self.active_connections[user_id]

            # Обновляем статус пользователя в Redis
            await online_status_service.set_user_offline(user_id)

            # Публикуем событие отключения в Redis Pub/Sub для других серверов
            await self._publish_user_event(user_id, "disconnect")

            logger.info(f"User {user_id} disconnected from server {self.server_id}")
            return True

        except Exception as e:
            logger.error(f"Error disconnecting user {user_id}: {str(e)}")
            return False

    async def send_personal_message(self, message: Dict[str, Any], user_id: str) -> bool:
        """
        Отправляет сообщение конкретному пользователю.

        Args:
            message: Словарь с данными сообщения
            user_id: ID пользователя-получателя

        Returns:
            True, если сообщение отправлено, False если пользователь не в сети или произошла ошибка
        """
        # Проверяем, подключен ли пользователь к текущему серверу
        if user_id in self.active_connections:
            try:
                websocket = self.active_connections[user_id]
                await websocket.send_text(json.dumps(message))
                logger.debug(f"Message sent to user {user_id} on this server")
                return True
            except Exception as e:
                logger.error(f"Error sending message to user {user_id}: {str(e)}")
                # Если отправка не удалась, отключаем пользователя
                await self.disconnect(user_id)
                # Сохраняем сообщение в буфер, чтобы пользователь получил его при следующем подключении
                await message_buffer.add_message(user_id, message)
                return False

        # Если пользователь не подключен к текущему серверу,
        # проверяем, подключен ли он к другому серверу
        if await online_status_service.is_user_online(user_id):
            # Пользователь подключен к другому серверу в кластере
            # Отправляем сообщение через Redis Pub/Sub
            sent = await self._publish_message_to_user(user_id, message)
            if sent:
                logger.debug(f"Message published to user {user_id} via Redis")
                return True

        # Если пользователь не в сети или отправка через Redis не удалась,
        # добавляем сообщение в буфер
        await message_buffer.add_message(user_id, message)
        logger.debug(f"Message added to buffer for offline user {user_id}")
        return False

    async def broadcast(self, message: Dict[str, Any], exclude: Optional[Set[str]] = None) -> int:
        """
        Отправляет сообщение всем подключенным пользователям.

        Args:
            message: Словарь с данными сообщения
            exclude: Набор ID пользователей, которым не нужно отправлять сообщение

        Returns:
            Количество пользователей, получивших сообщение
        """
        exclude = exclude or set()
        count = 0

        # Отправляем всем подключенным к текущему серверу
        for user_id, websocket in list(self.active_connections.items()):
            if user_id not in exclude:
                try:
                    await websocket.send_text(json.dumps(message))
                    count += 1
                except Exception as e:
                    logger.error(f"Error broadcasting to user {user_id}: {str(e)}")
                    await self.disconnect(user_id)

        # Публикуем для всех серверов в кластере
        try:
            await self._publish_broadcast(message, exclude, self.server_id)
            # Учитываем только локальные отправки в счетчике
        except Exception as e:
            logger.error(f"Error publishing broadcast: {str(e)}")

        return count

    async def broadcast_to_users(self, message: Dict[str, Any], user_ids: List[str]) -> int:
        """
        Отправляет сообщение указанным пользователям.

        Args:
            message: Словарь с данными сообщения
            user_ids: Список ID пользователей-получателей

        Returns:
            Количество пользователей, получивших сообщение
        """
        count = 0
        for user_id in user_ids:
            if await self.send_personal_message(message, user_id):
                count += 1
        return count

    async def is_connected(self, user_id: str) -> bool:
        """
        Проверяет, подключен ли пользователь.

        Args:
            user_id: ID пользователя

        Returns:
            True, если пользователь подключен к какому-либо серверу
        """
        # Проверяем локальное подключение
        if user_id in self.active_connections:
            return True

        # Проверяем статус в Redis
        return await online_status_service.is_user_online(user_id)

    async def _publish_user_event(self, user_id: str, event_type: str) -> bool:
        """
        Публикует событие о пользователе в Redis Pub/Sub.

        Args:
            user_id: ID пользователя
            event_type: Тип события ('connect' или 'disconnect')

        Returns:
            True, если событие опубликовано успешно
        """
        try:
            # В текущей реализации мы не используем Redis Pub/Sub для межсерверного
            # взаимодействия, но это место, где оно было бы реализовано
            # для кластерной работы серверов

            # redis_client = await RedisManager.get_status_redis()
            # try:
            #     channel = "user_events"
            #     message = {
            #         "user_id": user_id,
            #         "event": event_type,
            #         "server_id": self.server_id,
            #         "timestamp": datetime.utcnow().isoformat()
            #     }
            #     await redis_client.publish(channel, serialize_json(message))
            #     return True
            # finally:
            #     await redis_client.close()

            # Пока просто возвращаем True
            return True

        except Exception as e:
            logger.error(f"Error publishing user event: {str(e)}")
            return False

    async def _publish_message_to_user(self, user_id: str, message: Dict[str, Any]) -> bool:
        """
        Публикует сообщение для пользователя через Redis Pub/Sub.

        Args:
            user_id: ID пользователя-получателя
            message: Словарь с данными сообщения

        Returns:
            True, если сообщение опубликовано успешно
        """
        try:
            # В текущей реализации мы не используем Redis Pub/Sub для межсерверного
            # взаимодействия, так как у нас один сервер

            # redis_client = await RedisManager.get_status_redis()
            # try:
            #     channel = f"user_messages:{user_id}"
            #     wrapper = {
            #         "server_id": self.server_id,
            #         "timestamp": datetime.utcnow().isoformat(),
            #         "message": message
            #     }
            #     await redis_client.publish(channel, serialize_json(wrapper))
            #     return True
            # finally:
            #     await redis_client.close()

            # Пока просто добавляем в буфер
            await message_buffer.add_message(user_id, message)
            return False  # Возвращаем False, чтобы вызывающий код знал, что сообщение не было доставлено немедленно

        except Exception as e:
            logger.error(f"Error publishing message to user: {str(e)}")
            return False

    async def _publish_broadcast(self, message: Dict[str, Any], exclude: Set[str], sender_server_id: str) -> bool:
        """
        Публикует широковещательное сообщение через Redis Pub/Sub.

        Args:
            message: Словарь с данными сообщения
            exclude: Набор ID пользователей, которым не нужно отправлять сообщение
            sender_server_id: ID сервера-отправителя

        Returns:
            True, если сообщение опубликовано успешно
        """
        try:
            # В текущей реализации мы не используем Redis Pub/Sub для межсерверного
            # взаимодействия, так как у нас один сервер

            # redis_client = await RedisManager.get_status_redis()
            # try:
            #     channel = "broadcast_messages"
            #     wrapper = {
            #         "server_id": sender_server_id,
            #         "timestamp": datetime.utcnow().isoformat(),
            #         "message": message,
            #         "exclude": list(exclude)
            #     }
            #     await redis_client.publish(channel, serialize_json(wrapper))
            #     return True
            # finally:
            #     await redis_client.close()

            # Пока просто возвращаем True
            return True

        except Exception as e:
            logger.error(f"Error publishing broadcast: {str(e)}")
            return False

    async def get_online_status_report(self) -> Dict[str, Any]:
        """
        Возвращает отчет о текущих активных соединениях.

        Returns:
            Словарь с информацией о пользователях онлайн
        """
        try:
            # Получаем локальные подключения
            local_connections = set(self.active_connections.keys())

            # Получаем всех пользователей онлайн из Redis
            all_online = await online_status_service.get_online_users()
            all_online_set = set(all_online)

            # Пользователи, подключенные к другим серверам
            remote_connections = all_online_set - local_connections

            report = {
                "server_id": self.server_id,
                "timestamp": datetime.utcnow().isoformat(),
                "local_connections_count": len(local_connections),
                "remote_connections_count": len(remote_connections),
                "total_online_count": len(all_online_set),
                "local_users": list(local_connections),
                "total_online_users": all_online
            }

            return report

        except Exception as e:
            logger.error(f"Error generating online status report: {str(e)}")
            return {
                "server_id": self.server_id,
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e),
                "local_connections_count": len(self.active_connections)
            }


# Создаем глобальный экземпляр менеджера соединений
connection_manager = ConnectionManager()