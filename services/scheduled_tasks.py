import asyncio
import time
from datetime import datetime
import logging
from ..services.connection_manager import message_buffer, online_status_service
from ..services.secure_channel_service import secure_channel_service

logger = logging.getLogger(__name__)


async def cleanup_task():
    """
    Периодическая задача для очистки устаревших данных:
    - Устаревшие сообщения в буфере
    - Неактивные пользователи
    - Истекшие защищенные каналы
    """
    while True:
        try:
            logger.info("Running cleanup task...")

            # Очищаем буфер сообщений
            await message_buffer.cleanup_old_messages()

            # Очищаем статусы неактивных пользователей
            await online_status_service.cleanup_inactive_users()

            # Очищаем истекшие защищенные каналы
            secure_channel_service.cleanup_expired()

            logger.info("Cleanup task completed successfully")
        except Exception as e:
            logger.error(f"Error during cleanup task: {str(e)}")

        # Запускаем каждые 15 минут
        await asyncio.sleep(15 * 60)


def start_background_tasks():
    """
    Запускает все фоновые задачи
    """
    loop = asyncio.get_event_loop()
    task = loop.create_task(cleanup_task())
    return task