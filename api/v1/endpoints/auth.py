from fastapi import APIRouter, HTTPException, Depends
import json
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from ....database import get_db
from ....schemas.auth import (
    SecureChannelInit, EncryptedRequest, LoginData,
    RegisterData, AuthResponse, RefreshRequest, LogoutRequest
)
from ....core.security import (
    create_access_token, create_refresh_token,
    get_password_hash, verify_password
)
from ....services.secure_channel_service import SecureChannelService
from ....models.user import User, UserDevice
from ....core.crypto import CryptoService

router = APIRouter()
crypto_service = CryptoService()
secure_channel_service = SecureChannelService(crypto_service)


@router.post("/secure-init")
async def initialize_secure_channel(request: SecureChannelInit):
    try:
        encrypted_session_key = secure_channel_service.create_channel(
            request.channelId,
            request.publicKey
        )

        return {"sessionKey": encrypted_session_key}
    except Exception as e:
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=400,
            detail=f"Failed to initialize secure channel: {str(e)}"
        )


@router.post("/register", response_model=dict)
async def register(request: EncryptedRequest, db: Session = Depends(get_db)):
    try:
        # Проверяем наличие канала
        channel = secure_channel_service.get_channel(request.channelId)
        if not channel:
            raise HTTPException(status_code=400, detail="Invalid or expired channel")
        # Расшифровываем данные
        try:
            decrypted_data = secure_channel_service.decrypt_data(
                request.channelId,
                request.data
            )
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

        # Парсим JSON
        try:
            register_data = RegisterData(**json.loads(decrypted_data))
        except Exception as e:
            print(f"JSON parsing error: {str(e)}")

        # Проверяем, существует ли пользователь
        existing_user = db.query(User).filter(User.email == register_data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )

        # Создаем пользователя
        try:
            hashed_password = get_password_hash(register_data.password)
            user = User(
                email=register_data.email,
                username=register_data.username,
                hashed_password=hashed_password
            )
            db.add(user)

            try:
                db.flush()
            except Exception as e:
                print(f"Error during flush: {str(e)}")
                db.rollback()
                raise

            # Создаем устройство
            from sqlalchemy.sql import func

            device = UserDevice(
                user_id=user.id,
                device_id=register_data.deviceId,
                last_login=func.now()
            )
            db.add(device)

            try:
                db.commit()
            except Exception as e:
                print(f"Error during commit: {str(e)}")
                db.rollback()
                raise

        except Exception as e:
            print(f"Database error: {str(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            raise HTTPException(
                status_code=400,
                detail=f"Error creating user: {str(e)}"
            )

        # Генерируем токены
        access_token = create_access_token({"sub": str(user.id)})
        refresh_token = create_refresh_token()

        # Обновляем refresh token устройства
        device.refresh_token = refresh_token
        db.commit()

        # Формируем и шифруем ответ
        response_data = AuthResponse(
            accessToken=access_token,
            refreshToken=refresh_token,
            deviceId=register_data.deviceId
        )

        encrypted_response = secure_channel_service.encrypt_data(
            request.channelId,
            json.dumps(response_data.dict())
        )

        return {"data": encrypted_response}

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Registration failed: {str(e)}"
        )
    finally:
        secure_channel_service.remove_channel(request.channelId)


@router.post("/login", response_model=dict)
async def login(request: EncryptedRequest, db: Session = Depends(get_db)):
    try:
        # Проверяем наличие канала
        channel = secure_channel_service.get_channel(request.channelId)
        if not channel:
            raise HTTPException(status_code=400, detail="Invalid or expired channel")
        # Расшифровываем данные
        try:
            decrypted_data = secure_channel_service.decrypt_data(
                request.channelId,
                request.data
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

        # Парсим JSON
        try:
            login_data = LoginData(**json.loads(decrypted_data))
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid login data format")

        # Ищем пользователя
        user = db.query(User).filter(User.email == login_data.email).first()
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Incorrect email or password"
            )

        # Проверяем пароль
        if not verify_password(login_data.password, user.hashed_password):
            raise HTTPException(
                status_code=401,
                detail="Incorrect email or password"
            )

        # Проверяем/создаем устройство
        device = (
            db.query(UserDevice)
            .filter(
                UserDevice.user_id == user.id,
                UserDevice.device_id == login_data.deviceId
            )
            .first()
        )

        if not device:
            device = UserDevice(
                user_id=user.id,
                device_id=login_data.deviceId
            )
            db.add(device)

        # Генерируем токены
        access_token = create_access_token({"sub": str(user.id)})
        refresh_token = create_refresh_token()

        # Обновляем refresh token устройства
        device.refresh_token = refresh_token
        device.last_login = func.now()

        try:
            db.commit()
        except Exception as e:
            db.rollback()
            raise HTTPException(
                status_code=500,
                detail="Database error during login"
            )

        # Формируем и шифруем ответ
        response_data = AuthResponse(
            accessToken=access_token,
            refreshToken=refresh_token,
            deviceId=login_data.deviceId
        )

        try:
            encrypted_response = secure_channel_service.encrypt_data(
                request.channelId,
                json.dumps(response_data.dict())
            )
            return {"data": encrypted_response}
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail="Error encrypting response"
            )

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Login failed: {str(e)}"
        )
    finally:
        secure_channel_service.remove_channel(request.channelId)


@router.post("/refresh", response_model=AuthResponse)
async def refresh_token(request: RefreshRequest, db: Session = Depends(get_db)):
    device = (
        db.query(UserDevice)
        .filter(
            UserDevice.device_id == request.deviceId,
            UserDevice.refresh_token == request.refreshToken
        )
        .first()
    )

    if not device:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    # Генерируем новые токены
    access_token = create_access_token({"sub": str(device.user_id)})
    refresh_token = create_refresh_token()

    # Обновляем refresh token устройства
    device.refresh_token = refresh_token
    db.commit()

    return AuthResponse(
        accessToken=access_token,
        refreshToken=refresh_token,
        deviceId=request.deviceId
    )


@router.post("/refresh", response_model=AuthResponse)
async def refresh_token(request: RefreshRequest, db: Session = Depends(get_db)):
    device = (
        db.query(UserDevice)
        .filter(
            UserDevice.device_id == request.deviceId,
            UserDevice.refresh_token == request.refreshToken
        )
        .first()
    )

    if not device:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    # Генерируем новые токены
    access_token = create_access_token({"sub": str(device.user_id)})
    refresh_token = create_refresh_token()

    # Обновляем refresh token устройства
    device.refresh_token = refresh_token
    db.commit()

    return AuthResponse(
        accessToken=access_token,
        refreshToken=refresh_token,
        deviceId=request.deviceId
    )


@router.post("/logout")
async def logout(request: LogoutRequest, db: Session = Depends(get_db)):
    device = (
        db.query(UserDevice)
        .filter(UserDevice.device_id == request.deviceId)
        .first()
    )

    if device:
        device.refresh_token = None
        db.commit()

    return {"status": "success"}