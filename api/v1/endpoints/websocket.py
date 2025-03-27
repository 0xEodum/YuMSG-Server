"""
WebSocket эндпоинты для FastAPI.
Обеспечивает обработку WebSocket соединений и обмен сообщениями.
"""
import json
import uuid
import asyncio
from datetime import datetime
from typing import Optional, Dict, Any, List
import logging
from fastapi import WebSocket, WebSocketDisconnect, Query, Depends, HTTPException
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from ....database import get_db
from ....models.user import User
from ....core.security import SECRET_KEY, ALGORITHM
from ....services.connection_manager import connection_manager
from ....services.online_status_service import online_status_service
from ....services.message_buffer import message_buffer

# Настройка логирования
logger = logging.getLogger(__name__)


async def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
    """Получает пользователя по ID"""
    user = db.query(User).filter(User.id == user_id).first()
    return user


async def verify_user_exists(db: Session, user_id: str) -> bool:
    """Проверяет существование пользователя"""
    user = await get_user_by_id(db, user_id)
    return user is not None and user.is_active


async def update_last_seen(db: Session, user_id: str):
    """Обновляет время последней активности пользователя"""
    user = await get_user_by_id(db, user_id)
    if user:
        user.last_seen = datetime.utcnow()
        db.commit()


async def handle_chat_init(message: Dict[str, Any], user_id: str, db: Session):
    """
    Обработчик инициализации чата.

    Args:
        message: Словарь с данными сообщения
        user_id: ID пользователя-инициатора
        db: Сессия базы данных
    """
    # Получаем данные сообщения
    data = message.get("data", {})
    recipient_id = data.get("recipientId")
    public_key = data.get("publicKey")

    if not recipient_id or not public_key:
        logger.warning(f"Missing recipient_id or public_key in chat init from user {user_id}")
        return

    # Проверяем существование получателя
    if not await verify_user_exists(db, recipient_id):
        logger.warning(f"Recipient {recipient_id} not found for chat init from user {user_id}")
        return

    # Генерируем случайный ID чата
    chat_id = str(uuid.uuid4())
    logger.info(f"Generated chat_id {chat_id} for users {user_id} and {recipient_id}")

    # Отправляем событие инициализации чата получателю
    event = {
        "type": "chat.init",
        "data": {
            "chatId": chat_id,
            "initiatorId": user_id,
            "publicKey": public_key
        }
    }

    # Отправляем или буферизуем сообщение для получателя
    await connection_manager.send_personal_message(event, recipient_id)

    # Отправляем подтверждение инициатору
    confirm_event = {
        "type": "chat.init.confirm",
        "data": {
            "chatId": chat_id,
            "recipientId": recipient_id
        }
    }
    await connection_manager.send_personal_message(confirm_event, user_id)


async def handle_key_exchange(message: Dict[str, Any], user_id: str, db: Session):
    """
    Обработчик обмена ключами.

    Args:
        message: Словарь с данными сообщения
        user_id: ID пользователя-отправителя
        db: Сессия базы данных
    """
    data = message.get("data", {})
    chat_id = data.get("chatId")
    recipient_id = data.get("recipientId", None)  # Может отсутствовать в некоторых сценариях
    public_key = data.get("publicKey")
    encrypted_partial_key = data.get("encryptedPartialKey")

    if not chat_id or not public_key or not encrypted_partial_key:
        logger.warning(f"Missing required data in key exchange from user {user_id}")
        return

    # Ищем получателя, если не указан явно
    if not recipient_id:
        # В реальной реализации здесь мог бы быть поиск получателя по chatId,
        # но т.к. сервер не хранит метаданные чатов, это не реализуемо
        logger.warning(f"Missing recipient_id in key exchange from user {user_id}")
        return

    # Проверяем существование получателя
    if not await verify_user_exists(db, recipient_id):
        logger.warning(f"Recipient {recipient_id} not found for key exchange from user {user_id}")
        return

    # Создаем событие для получателя
    event = {
        "type": "chat.key_exchange",
        "data": {
            "chatId": chat_id,
            "senderId": user_id,
            "publicKey": public_key,
            "encryptedPartialKey": encrypted_partial_key
        }
    }

    # Отправляем или буферизуем сообщение для получателя
    await connection_manager.send_personal_message(event, recipient_id)
    logger.info(f"Key exchange message sent from user {user_id} to {recipient_id} for chat {chat_id}")


async def handle_key_exchange_complete(message: Dict[str, Any], user_id: str, db: Session):
    """
    Обработчик завершения обмена ключами.

    Args:
        message: Словарь с данными сообщения
        user_id: ID пользователя-отправителя
        db: Сессия базы данных
    """
    data = message.get("data", {})
    chat_id = data.get("chatId")
    recipient_id = data.get("recipientId", None)
    encrypted_partial_key = data.get("encryptedPartialKey")

    if not chat_id or not encrypted_partial_key:
        logger.warning(f"Missing required data in key exchange complete from user {user_id}")
        return

    # Ищем получателя, если не указан явно
    if not recipient_id:
        logger.warning(f"Missing recipient_id in key exchange complete from user {user_id}")
        return

    # Проверяем существование получателя
    if not await verify_user_exists(db, recipient_id):
        logger.warning(f"Recipient {recipient_id} not found for key exchange complete from user {user_id}")
        return

    # Создаем событие для получателя
    event = {
        "type": "chat.key_exchange_complete",
        "data": {
            "chatId": chat_id,
            "senderId": user_id,
            "encryptedPartialKey": encrypted_partial_key
        }
    }

    # Отправляем или буферизуем сообщение для получателя
    await connection_manager.send_personal_message(event, recipient_id)
    logger.info(f"Key exchange complete message sent from user {user_id} to {recipient_id} for chat {chat_id}")


async def handle_chat_message(message: Dict[str, Any], user_id: str, db: Session):
    """
    Обработчик сообщений чата.

    Args:
        message: Словарь с данными сообщения
        user_id: ID пользователя-отправителя
        db: Сессия базы данных
    """
    data = message.get("data", {})
    chat_id = data.get("chatId")
    recipient_id = data.get("recipientId")
    content = data.get("content")  # Зашифрованное содержимое
    message_type = data.get("type", "text")
    metadata = data.get("metadata", {})

    if not chat_id or not content or not recipient_id:
        logger.warning(f"Missing required data in chat message from user {user_id}")
        return

    # Проверяем существование получателя
    if not await verify_user_exists(db, recipient_id):
        logger.warning(f"Recipient {recipient_id} not found for chat message from user {user_id}")
        return

    # Генерируем ID сообщения
    message_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()

    # Формируем сообщение с уникальным ID для получателя
    message_event = {
        "type": "chat.message",
        "data": {
            "messageId": message_id,
            "chatId": chat_id,
            "senderId": user_id,
            "content": content,  # Передаем зашифрованный контент как есть
            "type": message_type,
            "timestamp": timestamp,
            "metadata": metadata
        }
    }

    # Отправляем сообщение получателю
    recipient_received = await connection_manager.send_personal_message(message_event, recipient_id)

    # Определяем статус сообщения на основе результата отправки
    status = "delivered" if recipient_received else "sent"

    # Отправляем статус отправителю
    status_event = {
        "type": "chat.status",
        "data": {
            "messageId": message_id,
            "chatId": chat_id,
            "senderId": user_id,
            "status": status,
            "timestamp": datetime.utcnow().isoformat()
        }
    }

    await connection_manager.send_personal_message(status_event, user_id)
    logger.info(f"Chat message sent from user {user_id} to {recipient_id} for chat {chat_id}, status: {status}")


async def handle_message_status(message: Dict[str, Any], user_id: str, db: Session):
    """
    Обработчик статуса сообщения.

    Args:
        message: Словарь с данными сообщения
        user_id: ID пользователя, изменяющего статус
        db: Сессия базы данных
    """
    data = message.get("data", {})
    message_id = data.get("messageId")
    chat_id = data.get("chatId")
    status = data.get("status")
    recipient_id = data.get("recipientId")  # ID отправителя исходного сообщения

    if not message_id or not chat_id or not status:
        logger.warning(f"Missing required data in message status from user {user_id}")
        return

    if not recipient_id:
        logger.warning(f"Missing recipient_id in message status from user {user_id}")
        return

    # Проверяем существование отправителя
    if not await verify_user_exists(db, recipient_id):
        logger.warning(f"Recipient {recipient_id} not found for message status from user {user_id}")
        return

    # Формируем событие статуса для отправителя
    status_event = {
        "type": "chat.status",
        "data": {
            "messageId": message_id,
            "chatId": chat_id,
            "status": status,
            "timestamp": datetime.utcnow().isoformat()
        }
    }

    # Отправляем или буферизуем статус
    await connection_manager.send_personal_message(status_event, recipient_id)
    logger.info(f"Message status '{status}' sent from user {user_id} to {recipient_id} for message {message_id}")


async def websocket_endpoint(websocket: WebSocket, token: str = None, db: Session = None):
    """
    Основной WebSocket эндпоинт.

    Args:
        websocket: WebSocket соединение
        token: JWT токен для аутентификации
        db: Сессия базы данных
    """
    user_id = None

    # Проверяем токен
    try:
        if not token:
            logger.warning("WebSocket connection attempt without token")
            await websocket.close(code=1008)
            return

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            logger.warning("WebSocket connection with token missing 'sub' claim")
            await websocket.close(code=1008)
            return

        logger.info(f"WebSocket token verified for user {user_id}")
    except JWTError as e:
        logger.error(f"WebSocket JWT verification error: {str(e)}")
        await websocket.close(code=1008)
        return

    # Принимаем соединение и регистрируем пользователя
    await connection_manager.connect(user_id, websocket)
    logger.info(f"WebSocket connection established for user {user_id}")

    # Обновляем последнее время активности пользователя в БД
    await update_last_seen(db, user_id)

    # Доставляем буферизованные сообщения
    logger.info(f"Retrieving buffered messages for user {user_id}")
    buffered_messages = await message_buffer.get_messages(user_id)
    if buffered_messages:
        logger.info(f"Delivering {len(buffered_messages)} buffered messages to user {user_id}")
        for msg in buffered_messages:
            try:
                await websocket.send_text(json.dumps(msg))
            except Exception as e:
                logger.error(f"Error sending buffered message to user {user_id}: {str(e)}")

    try:
        # Основной цикл обработки сообщений
        while True:
            # Получаем сообщение от клиента
            data = await websocket.receive_text()
            message = json.loads(data)
            message_type = message.get("type")

            logger.debug(f"Received WebSocket message of type '{message_type}' from user {user_id}")

            # Обновляем время активности
            await online_status_service.set_user_online(user_id)
            await update_last_seen(db, user_id)

            # Обрабатываем разные типы сообщений
            if message_type == "ping":
                # Отправляем pong в ответ на ping
                await websocket.send_text(json.dumps({"type": "pong"}))
                logger.debug(f"Sent pong to user {user_id}")

            elif message_type == "chat.init":
                # Обрабатываем инициализацию чата
                await handle_chat_init(message, user_id, db)

            elif message_type == "chat.key_exchange":
                # Обрабатываем обмен ключами
                await handle_key_exchange(message, user_id, db)

            elif message_type == "chat.key_exchange_complete":
                # Обрабатываем завершение обмена ключами
                await handle_key_exchange_complete(message, user_id, db)

            elif message_type == "chat.message":
                # Обрабатываем отправку сообщения
                await handle_chat_message(message, user_id, db)

            elif message_type == "chat.status":
                # Обрабатываем обновление статуса сообщения
                await handle_message_status(message, user_id, db)

            else:
                logger.warning(f"Unknown message type '{message_type}' from user {user_id}")

    except WebSocketDisconnect:
        # Обрабатываем отключение клиента
        logger.info(f"WebSocket disconnected for user {user_id}")
        await connection_manager.disconnect(user_id)

    except Exception as e:
        # Обрабатываем прочие ошибки
        logger.error(f"WebSocket error for user {user_id}: {str(e)}")
        await connection_manager.disconnect(user_id)