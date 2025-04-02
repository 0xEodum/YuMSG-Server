"""
Обновленный WebSocket эндпоинт, объединяющий корректную обработку ping
и обогащение сообщений именами пользователей из базы данных.
"""
import json
import logging
from datetime import datetime
from typing import Optional

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


async def websocket_endpoint(websocket: WebSocket, token: str = None, db: Session = None):
    """
    Основной WebSocket эндпоинт с улучшенной логикой:
    - Корректная обработка ping сообщений
    - Обогащение сообщений информацией о пользователях
    """
    user_id = None
    current_user = None

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

        # Получаем текущего пользователя
        current_user = await get_user_by_id(db, user_id)
        if not current_user:
            logger.warning(f"User {user_id} not found in database")
            await websocket.close(code=1008)
            return

    except JWTError as e:
        logger.error(f"WebSocket JWT verification error: {str(e)}")
        await websocket.close(code=1008)
        return

    # Принимаем соединение и регистрируем пользователя
    await connection_manager.connect(user_id, websocket)
    logger.info(f"WebSocket connection established for user {user_id}")

    # Обновляем последнее время активности пользователя в БД
    if current_user:
        current_user.last_seen = datetime.utcnow()
        db.commit()

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

            # Проверяем тип сообщения
            if not "type" in message:
                logger.warning(f"Received message without type from user {user_id}")
                continue

            message_type = message.get("type")

            # Специальная обработка для ping-сообщений
            if message_type == "ping":
                logger.debug(f"Received ping from user {user_id}")

                # Обновляем время активности
                await online_status_service.set_user_online(user_id)
                if current_user:
                    current_user.last_seen = datetime.utcnow()
                    db.commit()

                # Отправляем pong в ответ
                try:
                    await websocket.send_text(json.dumps({"type": "pong"}))
                    logger.debug(f"Sent pong to user {user_id}")
                except Exception as e:
                    logger.error(f"Error sending pong to user {user_id}: {str(e)}")

                # Пропускаем дальнейшую обработку
                continue

            # Проверяем обязательные поля для всех остальных типов сообщений
            if not "recipient_id" in message:
                logger.warning(f"Received malformed message from user {user_id}: missing recipient_id field")
                continue

            recipient_id = message.get("recipient_id")
            message_data = message.get("data", {})

            logger.info(f"Received {message_type} message from user {user_id} to {recipient_id}")

            # Добавляем ID отправителя для безопасности
            message["sender_id"] = user_id

            # Обогащаем сообщения именами пользователей из базы данных
            if message_type == 'chat.init':
                # Добавляем имя инициатора из базы данных
                if current_user and current_user.username:
                    message_data['initiator_name'] = current_user.username
                    message['data'] = message_data
                    logger.info(f"Added initiator_name '{current_user.username}' to chat.init message")

            elif message_type == 'chat.key_exchange':
                # Добавляем имя отвечающего из базы данных
                if current_user and current_user.username:
                    message_data['responder_name'] = current_user.username
                    message['data'] = message_data
                    logger.info(f"Added responder_name '{current_user.username}' to chat.key_exchange message")

            # Если отправитель указан как получатель, игнорируем сообщение
            if recipient_id == user_id:
                logger.warning(f"User {user_id} attempting to send message to self, ignoring")
                continue

            # Обновляем время активности
            await online_status_service.set_user_online(user_id)
            if current_user:
                current_user.last_seen = datetime.utcnow()
                db.commit()

            # Отправляем сообщение получателю
            await connection_manager.send_personal_message(message, recipient_id)
            logger.info(f"Message of type {message_type} routed from {user_id} to {recipient_id}")

    except WebSocketDisconnect:
        # Обрабатываем отключение клиента
        logger.info(f"WebSocket disconnected for user {user_id}")
        await connection_manager.disconnect(user_id)

    except Exception as e:
        # Обрабатываем прочие ошибки
        logger.error(f"WebSocket error for user {user_id}: {str(e)}")
        import traceback
        logger.error(f"Error traceback: {traceback.format_exc()}")
        await connection_manager.disconnect(user_id)