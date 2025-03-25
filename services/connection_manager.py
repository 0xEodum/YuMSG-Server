from typing import Dict
from fastapi import WebSocket
from datetime import datetime, timedelta


class ConnectionManager:
    """
    Менеджер WebSocket соединений пользователей.
    Хранит и управляет активными соединениями.
    """

    def __init__(self):
        # user_id -> WebSocket
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        """Устанавливает соединение и добавляет его в список активных"""
        await websocket.accept()
        self.active_connections[user_id] = websocket

    async def disconnect(self, user_id: str):
        """Удаляет соединение из списка активных"""
        if user_id in self.active_connections:
            del self.active_connections[user_id]

    async def send_personal_message(self, message: dict, user_id: str):
        """Отправляет сообщение конкретному пользователю"""
        if user_id in self.active_connections:
            websocket = self.active_connections[user_id]
            try:
                import json
                await websocket.send_text(json.dumps(message))
                return True
            except Exception as e:
                print(f"Error sending message to user {user_id}: {str(e)}")
                await self.disconnect(user_id)
                return False
        return False

    def is_connected(self, user_id: str) -> bool:
        """Проверяет, подключен ли пользователь"""
        return user_id in self.active_connections


class OnlineStatusService:
    """
    Сервис для отслеживания онлайн-статуса пользователей.
    """

    def __init__(self):
        # user_id -> last_activity_timestamp
        self._online_users = {}

    async def set_user_online(self, user_id: str):
        """Устанавливает статус пользователя как 'онлайн'"""
        self._online_users[user_id] = datetime.utcnow()

    async def set_user_offline(self, user_id: str):
        """Устанавливает статус пользователя как 'оффлайн'"""
        if user_id in self._online_users:
            del self._online_users[user_id]

    async def is_user_online(self, user_id: str) -> bool:
        """Проверяет, онлайн ли пользователь"""
        if user_id not in self._online_users:
            return False

        # Пользователь считается онлайн, если активность была менее 5 минут назад
        last_activity = self._online_users[user_id]
        return datetime.utcnow() - last_activity < timedelta(minutes=5)

    async def cleanup_inactive_users(self):
        """Очищает статусы пользователей, неактивных более 5 минут"""
        current_time = datetime.utcnow()
        inactive_users = [
            user_id for user_id, last_activity in self._online_users.items()
            if current_time - last_activity > timedelta(minutes=5)
        ]

        for user_id in inactive_users:
            await self.set_user_offline(user_id)


class MessageBuffer:
    """
    Буфер для хранения сообщений, предназначенных для оффлайн пользователей.
    """

    def __init__(self, max_messages_per_user=100, max_age_days=7):
        # user_id -> list of messages
        self.buffer = {}
        self.max_messages_per_user = max_messages_per_user
        self.max_age = timedelta(days=max_age_days)

    async def add_message(self, user_id: str, message: dict):
        """Добавляет сообщение в буфер для конкретного пользователя"""
        if user_id not in self.buffer:
            self.buffer[user_id] = []

        # Добавляем временную метку для отслеживания возраста сообщения
        message_with_timestamp = {
            "message": message,
            "timestamp": datetime.utcnow()
        }

        self.buffer[user_id].append(message_with_timestamp)

        # Ограничиваем количество сообщений для пользователя
        if len(self.buffer[user_id]) > self.max_messages_per_user:
            self.buffer[user_id] = self.buffer[user_id][-self.max_messages_per_user:]

    async def get_messages(self, user_id: str):
        """Получает и удаляет все сообщения для пользователя"""
        if user_id not in self.buffer:
            return []

        messages = [item["message"] for item in self.buffer[user_id]]
        del self.buffer[user_id]
        return messages

    async def cleanup_old_messages(self):
        """Удаляет устаревшие сообщения из буфера"""
        current_time = datetime.utcnow()

        for user_id in list(self.buffer.keys()):
            # Фильтруем сообщения, оставляя только не старше max_age
            recent_messages = [
                item for item in self.buffer[user_id]
                if current_time - item["timestamp"] <= self.max_age
            ]

            if not recent_messages:
                del self.buffer[user_id]
            else:
                self.buffer[user_id] = recent_messages


# Создаем глобальные экземпляры для использования в приложении
connection_manager = ConnectionManager()
online_status_service = OnlineStatusService()
message_buffer = MessageBuffer()