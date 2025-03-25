from pydantic import BaseModel
from typing import Optional, Dict, Any, List

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

class TokenData(BaseModel):
    sub: Optional[str] = None
    username: Optional[str] = None
    exp: Optional[int] = None

class RefreshRequest(BaseModel):
    refreshToken: str
    deviceId: str

class LogoutRequest(BaseModel):
    deviceId: str

class UserProfile(BaseModel):
    id: str
    username: str
    email: str
    has_avatar: bool
    avatar_url: Optional[str] = None
    is_online: bool
    last_seen: Optional[str] = None

class UserSearch(BaseModel):
    query: str
    limit: int = 10

class UserSearchResult(BaseModel):
    id: str
    username: str
    avatarUrl: Optional[str] = None
    isOnline: bool

class UserSearchResponse(BaseModel):
    users: List[UserSearchResult]
    nextPageToken: Optional[str] = None