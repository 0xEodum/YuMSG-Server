from pydantic import BaseModel
from typing import Optional

class SecureChannelInit(BaseModel):
    channelId: str
    publicKey: str

class EncryptedRequest(BaseModel):
    channelId: str
    data: str  # Зашифрованные данные

class LoginData(BaseModel):
    email: str
    password: str
    deviceId: str

class RegisterData(BaseModel):
    username: str
    email: str
    password: str
    deviceId: str

class AuthResponse(BaseModel):
    accessToken: str
    refreshToken: str
    deviceId: str

class RefreshRequest(BaseModel):
    refreshToken: str
    deviceId: str

class LogoutRequest(BaseModel):
    deviceId: str