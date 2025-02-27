from datetime import datetime, timedelta
from typing import Dict, Optional
from ..core.crypto import CryptoService


class SecureChannel:
    def __init__(self, channel_id: str, public_key: str, session_key: bytes):
        self.channel_id = channel_id
        self.public_key = public_key
        self.session_key = session_key
        self.created_at = datetime.utcnow()
        self.expires_at = self.created_at + timedelta(minutes=30)  # Канал действителен 30 минут

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at


class SecureChannelService:
    def __init__(self, crypto_service: CryptoService):
        self._crypto_service = crypto_service
        self._channels: Dict[str, SecureChannel] = {}

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
        channel = self._channels.get(channel_id)

        if channel is None:
            return None

        if channel.is_expired:
            self.remove_channel(channel_id)
            return None

        return channel

    def decrypt_data(self, channel_id: str, encrypted_data: str) -> str:
        """Расшифровывает данные с помощью сессионного ключа канала"""
        print(f"Attempting to decrypt data for channel {channel_id}")

        channel = self.get_channel(channel_id)
        if not channel:
            print(f"Channel {channel_id} not found or expired")
            raise ValueError("Invalid or expired channel")

        print(f"Channel found, session key length: {len(channel.session_key)}")
        print(f"First 32 bytes of encrypted data: {encrypted_data[:32]}")

        try:
            decrypted = self._crypto_service.decrypt_with_session_key(
                encrypted_data,
                channel.session_key
            )
            print(f"Decryption successful. Result: {decrypted}")
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
        """Удаляет канал"""
        if channel_id in self._channels:
            del self._channels[channel_id]

    def cleanup_expired(self):
        """Очищает истекшие каналы"""
        expired = [
            channel_id
            for channel_id, channel in self._channels.items()
            if channel.is_expired
        ]
        for channel_id in expired:
            self.remove_channel(channel_id)