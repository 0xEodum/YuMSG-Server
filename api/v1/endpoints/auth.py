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
    get_password_hash, verify_password, get_current_user
)
from ....services.secure_channel_service import secure_channel_service
from ....models.user import User, UserDevice
from ....core.crypto import CryptoService
from ....api.deps import get_secure_channel_service

router = APIRouter()
crypto_service = CryptoService()


@router.post("/secure-init")
async def initialize_secure_channel(
        request: SecureChannelInit,
        svc=Depends(get_secure_channel_service)
):
    print(f"Initializing secure channel with ID: {request.channelId}")
    print(f"Current channels before init: {list(svc._channels.keys())}")

    try:
        encrypted_session_key = svc.create_channel(
            request.channelId,
            request.publicKey
        )

        print(f"Channel {request.channelId} initialized successfully")
        print(f"Current channels after init: {list(svc._channels.keys())}")

        return {"sessionKey": encrypted_session_key}
    except Exception as e:
        print(f"Error initializing secure channel: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=400,
            detail=f"Failed to initialize secure channel: {str(e)}"
        )


@router.post("/register", response_model=dict)
async def register(
        request: EncryptedRequest,
        db: Session = Depends(get_db),
        svc=Depends(get_secure_channel_service)
):
    try:
        # Не удаляем канал после регистрации, так как он может понадобиться для других операций
        print(f"Registering user with channel: {request.channelId}")
        print(f"Available channels: {list(svc._channels.keys())}")

        # Проверяем наличие канала
        channel = svc.get_channel(request.channelId)
        if not channel:
            raise HTTPException(status_code=400, detail="Invalid or expired channel")

        # Расшифровываем данные
        try:
            decrypted_data = svc.decrypt_data(
                request.channelId,
                request.data
            )
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

        # Парсим JSON
        try:
            register_data_dict = json.loads(decrypted_data)
            print(f"Parsed registration data: {register_data_dict}")
            register_data = RegisterData(**register_data_dict)
        except Exception as e:
            print(f"JSON parsing error: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid registration data format")

        # Проверяем, существует ли пользователь
        existing_user = db.query(User).filter(User.email == register_data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )

        existing_username = db.query(User).filter(User.username == register_data.username).first()
        if existing_username:
            raise HTTPException(
                status_code=400,
                detail="Username already taken"
            )

        # Создаем пользователя внутри транзакции
        try:
            # Создаем хеш пароля
            hashed_password = get_password_hash(register_data.password)

            # Создаем нового пользователя
            user = User(
                email=register_data.email,
                username=register_data.username,
                hashed_password=hashed_password,
                is_active=True,
                last_seen=func.now()
            )
            db.add(user)
            db.flush()  # Выполняем flush, чтобы получить ID пользователя

            # Запоминаем ID пользователя
            user_id = user.id
            print(f"Created user with ID: {user_id}")

            # Создаем устройство
            device = UserDevice(
                user_id=user_id,
                device_id=register_data.deviceId,
                last_login=func.now()
            )
            db.add(device)
            db.flush()

            # Генерируем токены
            print(f"Generating tokens for user ID: {user_id}")
            access_token = create_access_token({"user_id": str(user_id), "username": user.username})
            refresh_token = create_refresh_token()

            # Обновляем refresh token устройства
            device.refresh_token = refresh_token

            # Коммит транзакции
            db.commit()
            print(f"Database commit successful")

            # Формируем ответ
            response_data = AuthResponse(
                accessToken=access_token,
                refreshToken=refresh_token,
                deviceId=register_data.deviceId
            )

            # Шифруем ответ
            print(f"Encrypting response")
            encrypted_response = svc.encrypt_data(
                request.channelId,
                json.dumps(response_data.dict())
            )
            print(f"Response encrypted successfully")

            return {"data": encrypted_response}

        except Exception as e:
            db.rollback()
            print(f"Registration error: {str(e)}")
            import traceback
            traceback_str = traceback.format_exc()
            print(f"Traceback: {traceback_str}")
            raise HTTPException(
                status_code=500,
                detail=f"Registration failed: {str(e)}"
            )

    except HTTPException:
        raise
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Registration failed: {str(e)}"
        )


@router.post("/login", response_model=dict)
async def login(
        request: EncryptedRequest,
        db: Session = Depends(get_db),
        svc=Depends(get_secure_channel_service)
):
    try:
        # Не удаляем канал после входа, он может понадобиться для других операций
        print(f"Login request using channel: {request.channelId}")
        print(f"Available channels: {list(svc._channels.keys())}")

        # Проверяем наличие канала
        channel = svc.get_channel(request.channelId)
        if not channel:
            raise HTTPException(status_code=400, detail="Invalid or expired channel")

        # Расшифровываем данные
        try:
            decrypted_data = svc.decrypt_data(
                request.channelId,
                request.data
            )
            print(f"Decrypted login data: {decrypted_data}")
        except Exception as e:
            print(f"Login decryption error: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

        # Парсим JSON
        try:
            login_data_dict = json.loads(decrypted_data)
            print(f"Parsed login data: {login_data_dict}")
            login_data = LoginData(**login_data_dict)
        except Exception as e:
            print(f"JSON parsing error: {str(e)}")
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

        # Начинаем единую транзакцию для всех операций
        try:
            # Обновляем время последней активности
            user.last_seen = func.now()

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
                db.flush()

            # Обновляем время последнего входа
            device.last_login = func.now()

            # Генерируем токены
            print(f"Generating tokens for user ID: {user.id}")
            access_token = create_access_token({"user_id": str(user.id), "username": user.username})
            refresh_token = create_refresh_token()

            # Обновляем refresh token устройства
            device.refresh_token = refresh_token

            # Коммит всех изменений
            db.commit()
            print(f"Login database commit successful")

            # Формируем и шифруем ответ
            response_data = AuthResponse(
                accessToken=access_token,
                refreshToken=refresh_token,
                deviceId=login_data.deviceId
            )

            print(f"Encrypting login response")
            encrypted_response = svc.encrypt_data(
                request.channelId,
                json.dumps(response_data.dict())
            )
            print(f"Login response encrypted successfully")

            return {"data": encrypted_response}

        except Exception as e:
            db.rollback()
            print(f"Login transaction error: {str(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            raise HTTPException(
                status_code=500,
                detail=f"Login processing failed: {str(e)}"
            )

    except HTTPException:
        raise
    except Exception as e:
        print(f"Unexpected login error: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Login failed: {str(e)}"
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