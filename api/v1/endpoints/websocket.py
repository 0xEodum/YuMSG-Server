import json
import uuid
from datetime import datetime
from typing import Optional, Dict
from fastapi import WebSocket, WebSocketDisconnect, Query, Depends, HTTPException
from jose import jwt, JWTError

from ....core.security import SECRET_KEY, ALGORITHM
from ....services.connection_manager import connection_manager, online_status_service, message_buffer
from ....database import get_db
from ....models.user import User
from sqlalchemy.orm import Session
from sqlalchemy import select


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


async def handle_chat_init(message: dict, user_id: str, db: Session):
    """Обработчик инициализации чата"""
    # Получаем данные сообщения
    data = message.get("data", {})
    recipient_id = data.get("recipientId")
    public_key = data.get("publicKey")

    if not recipient_id or not public_key:
        return

    # Проверяем существование получателя
    if not await verify_user_exists(db, recipient_id):
        return

    # Генерируем случайный ID чата
    chat_id = str(uuid.uuid4())

    # Отправляем событие инициализации чата получателю
    event = {
        "type": "chat.init",
        "data": {
            "chatId": chat_id,
            "initiatorId": user_id,
            "publicKey": public_key
        }
    }

    if await connection_manager.is_connected(recipient_id):
        await connection_manager.send_personal_message(event, recipient_id)
    else:
        # Буферизуем сообщение для оффлайн получателя
        await message_buffer.add_message(recipient_id, event)

    # Отправляем подтверждение инициатору
    confirm_event = {
        "type": "chat.init.confirm",
        "data": {
            "chatId": chat_id,
            "recipientId": recipient_id
        }
    }
    await connection_manager.send_personal_message(confirm_event, user_id)


async def handle_key_exchange(message: dict, user_id: str, db: Session):
    """Обработчик обмена ключами"""
    data = message.get("data", {})
    chat_id = data.get("chatId")
    recipient_id = data.get("recipientId", None)  # Может отсутствовать в некоторых сценариях
    public_key = data.get("publicKey")
    encrypted_partial_key = data.get("encryptedPartialKey")

    if not chat_id or not public_key or not encrypted_partial_key:
        return

    # Ищем получателя, если не указан явно
    if not recipient_id:
        # В реальной реализации здесь мог бы быть поиск получателя по chatId,
        # но т.к. сервер не хранит метаданные чатов, это не реализуемо
        return

    # Проверяем существование получателя
    if not await verify_user_exists(db, recipient_id):
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

    # Отправляем или буферизуем сообщение
    if await connection_manager.is_connected(recipient_id):
        await connection_manager.send_personal_message(event, recipient_id)
    else:
        await message_buffer.add_message(recipient_id, event)


async def handle_key_exchange_complete(message: dict, user_id: str, db: Session):
    """Обработчик завершения обмена ключами"""
    data = message.get("data", {})
    chat_id = data.get("chatId")
    recipient_id = data.get("recipientId", None)
    encrypted_partial_key = data.get("encryptedPartialKey")

    if not chat_id or not encrypted_partial_key:
        return

    # Ищем получателя, если не указан явно
    if not recipient_id:
        return

    # Проверяем существование получателя
    if not await verify_user_exists(db, recipient_id):
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

    # Отправляем или буферизуем сообщение
    if await connection_manager.is_connected(recipient_id):
        await connection_manager.send_personal_message(event, recipient_id)
    else:
        await message_buffer.add_message(recipient_id, event)


async def handle_chat_message(message: dict, user_id: str, db: Session):
    """Обработчик сообщений чата"""
    data = message.get("data", {})
    chat_id = data.get("chatId")
    recipient_id = data.get("recipientId")
    content = data.get("content")  # Зашифрованное содержимое
    message_type = data.get("type", "text")
    metadata = data.get("metadata", {})

    if not chat_id or not content or not recipient_id:
        return

    # Проверяем существование получателя
    if not await verify_user_exists(db, recipient_id):
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

    # Отправляем или буферизуем сообщение для получателя
    recipient_online = False
    if await connection_manager.is_connected(recipient_id):
        recipient_online = await connection_manager.send_personal_message(message_event, recipient_id)

    if not recipient_online:
        await message_buffer.add_message(recipient_id, message_event)

    # Отправляем статус отправителю
    status_event = {
        "type": "chat.status",
        "data": {
            "messageId": message_id,
            "chatId": chat_id,
            "senderId": user_id,
            "status": "delivered" if recipient_online else "sent",
            "timestamp": datetime.utcnow().isoformat()
        }
    }

    await connection_manager.send_personal_message(status_event, user_id)


async def handle_message_status(message: dict, user_id: str, db: Session):
    """Обработчик статуса сообщения"""
    data = message.get("data", {})
    message_id = data.get("messageId")
    chat_id = data.get("chatId")
    status = data.get("status")

    if not message_id or not chat_id or not status:
        return

    # Находим отправителя сообщения
    # В реальной реализации нужен механизм связи messageId с senderId,
    # но т.к. сервер не хранит сообщения, используем recipientId из запроса
    recipient_id = data.get("recipientId")

    if not recipient_id:
        return

    # Проверяем существование отправителя
    if not await verify_user_exists(db, recipient_id):
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
    if await connection_manager.is_connected(recipient_id):
        await connection_manager.send_personal_message(status_event, recipient_id)
    else:
        await message_buffer.add_message(recipient_id, status_event)


async def websocket_endpoint(websocket: WebSocket, token: str = None, db: Session = None):
    """Основной WebSocket эндпоинт"""
    user_id = None

    # Проверяем токен
    try:
        if not token:
            await websocket.close(code=1008)
            return

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return

    # Принимаем соединение
    await connection_manager.connect(user_id, websocket)

    # Регистрируем пользователя как онлайн
    await online_status_service.set_user_online(user_id)

    # Обновляем последнее время активности пользователя
    await update_last_seen(db, user_id)

    # Доставляем буферизованные сообщения
    buffered_messages = await message_buffer.get_messages(user_id)
    for message in buffered_messages:
        try:
            await websocket.send_text(json.dumps(message))
        except Exception as e:
            print(f"Error sending buffered message: {str(e)}")

    try:
        # Основной цикл обработки сообщений
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            # Обновляем время активности
            await online_status_service.set_user_online(user_id)
            await update_last_seen(db, user_id)

            # Обрабатываем разные типы сообщений
            if message.get("type") == "ping":
                # Отправляем pong в ответ на ping
                await websocket.send_text(json.dumps({"type": "pong"}))

            elif message.get("type") == "chat.init":
                # Обрабатываем инициализацию чата
                await handle_chat_init(message, user_id, db)

            elif message.get("type") == "chat.key_exchange":
                # Обрабатываем обмен ключами
                await handle_key_exchange(message, user_id, db)

            elif message.get("type") == "chat.key_exchange_complete":
                # Обрабатываем завершение обмена ключами
                await handle_key_exchange_complete(message, user_id, db)

            elif message.get("type") == "chat.message":
                # Обрабатываем отправку сообщения
                await handle_chat_message(message, user_id, db)

            elif message.get("type") == "chat.status":
                # Обрабатываем обновление статуса сообщения
                await handle_message_status(message, user_id, db)

    except WebSocketDisconnect:
        # Отключаем пользователя
        await connection_manager.disconnect(user_id)
        await online_status_service.set_user_offline(user_id)
    except Exception as e:
        print(f"WebSocket error: {str(e)}")
        await connection_manager.disconnect(user_id)
        await online_status_service.set_user_offline(user_id)