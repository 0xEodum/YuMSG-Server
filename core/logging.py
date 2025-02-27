import logging
import json
from datetime import datetime
from fastapi import Request, Response
from typing import Callable
import sys


# Настройка логгера
def setup_logger():
    logger = logging.getLogger("chat_server")
    logger.setLevel(logging.INFO)

    # Форматтер для консоли
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )

    # Хендлер для консоли
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Хендлер для файла
    file_handler = logging.FileHandler("server.log")
    file_handler.setFormatter(console_formatter)
    logger.addHandler(file_handler)

    return logger


logger = setup_logger()


# Middleware для логирования запросов
async def logging_middleware(request: Request, call_next: Callable) -> Response:
    start_time = datetime.utcnow()

    # Подготовка информации о запросе
    request_info = {
        "timestamp": start_time.isoformat(),
        "method": request.method,
        "path": request.url.path,
        "query_params": str(request.query_params),
        "client": request.client.host if request.client else None,
    }

    # Логируем входящий запрос
    logger.info(f"Incoming request: {json.dumps(request_info)}")

    try:
        # Выполняем запрос
        response = await call_next(request)

        # Подготовка информации об ответе
        response_info = {
            "status_code": response.status_code,
            "processing_time_ms": (datetime.utcnow() - start_time).total_seconds() * 1000,
        }

        # Логируем ответ
        logger.info(f"Response sent: {json.dumps(response_info)}")

        return response

    except Exception as e:
        # Логируем ошибку
        logger.error(f"Request failed: {str(e)}", exc_info=True)
        raise