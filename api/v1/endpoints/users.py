from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from sqlalchemy import or_
from ....database import get_db
from ....models.user import User
from ....schemas.auth import EncryptedRequest
from ....core.security import get_current_user
from ....services.secure_channel_service import secure_channel_service
from ....services.online_status_service import online_status_service
from ....api.deps import get_secure_channel_service
from pathlib import Path
import json
import uuid
import os
import shutil
import logging

# Настройка логирования
logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/search")
async def search_users(
        request: EncryptedRequest,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_user),
        svc=Depends(get_secure_channel_service)
):
    try:
        logger.info(f"Search request received, channel: {request.channelId}")
        logger.info(f"Current user from token: {current_user}")

        # Получаем и проверяем канал
        channel = await svc.get_channel(request.channelId)
        if not channel:
            logger.error(f"Channel {request.channelId} not found or expired")
            raise HTTPException(status_code=400, detail="Invalid or expired channel")

        # Расшифровываем данные
        try:
            decrypted_data = await svc.decrypt_data(
                request.channelId,
                request.data
            )
            logger.info(f"Decrypted search data: {decrypted_data}")
        except Exception as e:
            logger.error(f"Search decryption error: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

        # Парсим JSON
        try:
            search_data = json.loads(decrypted_data)
            logger.info(f"Parsed search data: {search_data}")
            query = search_data.get('query', '')
            limit = search_data.get('limit', 10)
        except Exception as e:
            logger.error(f"JSON parsing error: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid request format")

        # Получаем ID текущего пользователя
        current_user_id = current_user.get('sub')
        if not current_user_id:
            logger.error(f"Missing sub in current_user: {current_user}")
            raise HTTPException(status_code=401, detail="Invalid authentication")

        logger.info(f"Searching users with query '{query}', excluding user {current_user_id}")

        # Ищем пользователей по имени или email (исключая текущего пользователя)
        users = db.query(User).filter(
            User.id != current_user_id,
            User.is_active == True,
            or_(
                User.username.ilike(f"%{query}%"),
                User.email.ilike(f"%{query}%")
            )
        ).limit(limit).all()

        logger.info(f"Found {len(users)} users")

        # Формируем результаты - вместо объекта вернем просто массив
        results = []
        for user in users:
            # Проверяем статус онлайн
            is_online = await online_status_service.is_user_online(str(user.id))

            # Формируем URL аватара (без /api префикса)
            avatar_url = f"/users/{user.id}/avatar" if user.has_avatar else None

            results.append({
                "id": str(user.id),
                "username": user.username,
                "avatarUrl": avatar_url,
                "isOnline": is_online
            })

        # Клиент ожидает просто массив, а не объект с полем "users"
        logger.info(f"Encrypting search results: {results}")
        encrypted_response = await svc.encrypt_data(
            request.channelId,
            json.dumps(results)
        )

        return {"data": encrypted_response}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in search_users: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.post("/me/avatar")
async def upload_avatar(
        file: UploadFile = File(...),
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    try:
        # Проверяем тип файла
        if not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="File must be an image")

        user_id = current_user.get('sub')
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Создаем директорию для аватаров, если она не существует
        avatar_dir = Path("avatars")
        avatar_dir.mkdir(exist_ok=True)

        # Генерируем уникальное имя файла
        file_extension = file.filename.split('.')[-1]
        filename = f"{user_id}_{uuid.uuid4()}.{file_extension}"
        file_path = avatar_dir / filename

        # Сохраняем файл
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)

        # Если у пользователя уже был аватар, удаляем старый файл
        if user.has_avatar and user.avatar_path:
            try:
                old_avatar_path = Path(user.avatar_path)
                if old_avatar_path.exists():
                    os.remove(old_avatar_path)
            except Exception as e:
                logger.error(f"Error removing old avatar: {str(e)}")

        # Обновляем информацию о пользователе
        user.has_avatar = True
        user.avatar_path = str(file_path)
        db.commit()

        return {"message": "Avatar uploaded successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload avatar: {str(e)}")


@router.get("/{user_id}/avatar")
async def get_avatar(user_id: int, db: Session = Depends(get_db)):
    # Получаем пользователя
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.has_avatar:
        # Возвращаем стандартный аватар
        default_avatar = Path("avatars/default.png")
        if not default_avatar.exists():
            # Создаем директорию, если не существует
            Path("avatars").mkdir(exist_ok=True)
            # Создаем пустой аватар по умолчанию
            from PIL import Image
            img = Image.new('RGB', (200, 200), color=(73, 109, 137))
            img.save(default_avatar)

        return FileResponse(default_avatar)

    # Проверяем существование файла
    avatar_path = Path(user.avatar_path)
    if not avatar_path.exists():
        user.has_avatar = False
        db.commit()
        return FileResponse("avatars/default.png")

    # Возвращаем аватар пользователя
    return FileResponse(avatar_path)