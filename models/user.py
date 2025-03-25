from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from ..database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Добавляем поля для аватара
    has_avatar = Column(Boolean, default=False)
    avatar_path = Column(String, nullable=True)

    # Добавляем поле для отслеживания последней активности
    last_seen = Column(DateTime(timezone=True), nullable=True)

    # Отношение к устройствам
    devices = relationship("UserDevice", back_populates="user", cascade="all, delete-orphan")


class UserDevice(Base):
    __tablename__ = "user_devices"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    device_id = Column(String, nullable=False)
    refresh_token = Column(String, nullable=True)
    last_login = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Отношение к пользователю
    user = relationship("User", back_populates="devices")

    class Config:
        orm_mode = True