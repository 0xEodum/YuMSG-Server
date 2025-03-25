from datetime import datetime, timedelta
from typing import Dict, Optional, Any
import json
import os
import pickle
from pathlib import Path
from ..core.crypto import CryptoService


class SecureChannel:
    def __init__(self, channel_id: str, public_key: str, session_key: bytes):
        self.channel_id = channel_id
        self.public_key = public_key
        self.session_key = session_key
        self.created_at = datetime.utcnow()
        # Увеличим время жизни канала до 30 минут
        self.expires_at = self.created_at + timedelta(minutes=30)

    @property
    def is_expired(self) -> bool:
        now = datetime.utcnow()
        is_expired = now > self.expires_at
        time_left = self.expires_at - now if not is_expired else timedelta(0)
        print(f"Channel {self.channel_id} expired: {is_expired}, time left: {time_left}")
        return is_expired

    def to_dict(self) -> dict:
        """Преобразует канал в словарь для сериализации"""
        return {
            "channel_id": self.channel_id,
            "public_key": self.public_key,
            "session_key": self.session_key,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat()
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'SecureChannel':
        """Создает экземпляр канала из словаря"""
        channel = cls(
            channel_id=data["channel_id"],
            public_key=data["public_key"],
            session_key=data["session_key"]
        )
        channel.created_at = datetime.fromisoformat(data["created_at"])
        channel.expires_at = datetime.fromisoformat(data["expires_at"])
        return channel


class SecureChannelService:
    """
    Сервис для управления защищенными каналами связи.
    Обеспечивает создание, хранение и использование каналов для шифрования данных.
    """

    def __init__(self, crypto_service: CryptoService):
        self._crypto_service = crypto_service
        self._channels: Dict[str, SecureChannel] = {}
        # Путь для хранения состояния каналов
        self._channels_dir = Path("secure_channels")
        self._channels_dir.mkdir(exist_ok=True)
        # Загружаем существующие каналы
        self._load_channels()

    def _save_channel(self, channel: SecureChannel):
        """Сохраняет канал в файл"""
        try:
            channel_path = self._channels_dir / f"{channel.channel_id}.json"
            with open(channel_path, 'wb') as f:
                pickle.dump(channel, f)
            print(f"Channel {channel.channel_id} saved to file")
        except Exception as e:
            print(f"Error saving channel {channel.channel_id}: {str(e)}")

    def _load_channels(self):
        """Загружает все каналы из файлов"""
        try:
            count = 0
            for channel_file in self._channels_dir.glob("*.json"):
                try:
                    with open(channel_file, 'rb') as f:
                        channel = pickle.load(f)

                    # Проверяем, не истек ли канал
                    if not channel.is_expired:
                        self._channels[channel.channel_id] = channel
                        count += 1
                    else:
                        # Удаляем файл истекшего канала
                        channel_file.unlink()
                except Exception as e:
                    print(f"Error loading channel from {channel_file}: {str(e)}")

            print(f"Loaded {count} channels from files")
        except Exception as e:
            print(f"Error loading channels: {str(e)}")

    def create_channel(self, channel_id: str, client_public_key: str) -> str:
        """Создает новый защищенный канал и возвращает зашифрованный сессионный ключ"""
        try:
            print(f"Creating channel with ID: {channel_id}")

            # Генерируем сессионный ключ
            session_key = self._crypto_service.generate_session_key()
            print(f"Generated session key length: {len(session_key)} bytes")

            # Создаем канал
            channel = SecureChannel(
                channel_id=channel_id,
                public_key=client_public_key,
                session_key=session_key
            )
            self._channels[channel_id] = channel
            print(f"Channel created and stored. Total channels: {len(self._channels)}")

            # Сохраняем канал
            self._save_channel(channel)

            # Шифруем сессионный ключ публичным ключом клиента
            print("Attempting to encrypt session key...")
            encrypted_key = self._crypto_service.encrypt_session_key(
                session_key,
                client_public_key
            )
            print(f"Session key encrypted. Encrypted length: {len(encrypted_key)}")

            return encrypted_key

        except Exception as e:
            print(f"Error in create_channel: {str(e)}")
            print(f"Error type: {type(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            raise

    def get_channel(self, channel_id: str) -> Optional[SecureChannel]:
        """Получает канал по ID и проверяет его валидность"""
        print(f"Looking for channel: {channel_id}, available channels: {list(self._channels.keys())}")

        # Сначала пытаемся найти канал в памяти
        channel = self._channels.get(channel_id)

        # Если канала нет в памяти, пытаемся загрузить его из файла
        if channel is None:
            try:
                channel_path = self._channels_dir / f"{channel_id}.json"
                if channel_path.exists():
                    with open(channel_path, 'rb') as f:
                        channel = pickle.load(f)

                    # Добавляем канал в память
                    self._channels[channel_id] = channel
                    print(f"Channel {channel_id} loaded from file")
                else:
                    print(f"No file for channel {channel_id}")
            except Exception as e:
                print(f"Error loading channel {channel_id} from file: {str(e)}")

        if channel is None:
            print(f"Channel {channel_id} not found")
            return None

        if channel.is_expired:
            print(f"Channel {channel_id} is expired")
            self.remove_channel(channel_id)
            return None

        print(f"Channel {channel_id} found and valid")
        return channel

    def decrypt_data(self, channel_id: str, encrypted_data: str) -> str:
        """Расшифровывает данные с помощью сессионного ключа канала"""
        print(f"Attempting to decrypt data for channel {channel_id}")

        channel = self.get_channel(channel_id)
        if not channel:
            print(f"Channel {channel_id} not found or expired")
            raise ValueError("Invalid or expired channel")

        print(f"Channel found, session key length: {len(channel.session_key)}")
        try:
            print(f"First 32 bytes of encrypted data: {encrypted_data[:min(32, len(encrypted_data))]}")
        except Exception as e:
            print(f"Error printing encrypted data: {str(e)}")

        try:
            decrypted = self._crypto_service.decrypt_with_session_key(
                encrypted_data,
                channel.session_key
            )
            print(f"Decryption successful. Result length: {len(decrypted)}")
            return decrypted
        except Exception as e:
            print(f"Decryption failed: {str(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            raise

    def encrypt_data(self, channel_id: str, data: str) -> str:
        """Шифрует данные с помощью сессионного ключа канала"""
        channel = self.get_channel(channel_id)
        if not channel:
            raise ValueError("Invalid or expired channel")

        return self._crypto_service.encrypt_with_session_key(
            data,
            channel.session_key
        )

    def remove_channel(self, channel_id: str):
        """Удаляет канал из памяти и из файла"""
        if channel_id in self._channels:
            del self._channels[channel_id]
            print(f"Channel {channel_id} removed from memory")

        # Удаляем файл канала, если он существует
        try:
            channel_path = self._channels_dir / f"{channel_id}.json"
            if channel_path.exists():
                channel_path.unlink()
                print(f"Channel {channel_id} file removed")
        except Exception as e:
            print(f"Error removing channel {channel_id} file: {str(e)}")

    def cleanup_expired(self):
        """Очищает истекшие каналы"""
        # Проверяем каналы в памяти
        expired = [
            channel_id
            for channel_id, channel in self._channels.items()
            if channel.is_expired
        ]
        for channel_id in expired:
            self.remove_channel(channel_id)

        # Проверяем каналы в файлах
        try:
            for channel_file in self._channels_dir.glob("*.json"):
                try:
                    with open(channel_file, 'rb') as f:
                        channel = pickle.load(f)

                    if channel.is_expired:
                        channel_file.unlink()
                        print(f"Expired channel file {channel_file.name} removed")
                except Exception as e:
                    print(f"Error checking channel file {channel_file}: {str(e)}")
        except Exception as e:
            print(f"Error cleaning up channel files: {str(e)}")


# Создаем глобальный экземпляр сервиса
from ..core.crypto import CryptoService

crypto_service = CryptoService()
secure_channel_service = SecureChannelService(crypto_service)