from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64


class CryptoService:
    def __init__(self):
        self._backend = default_backend()

    def generate_server_keypair(self):
        """Генерация пары ключей RSA для сервера"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self._backend
        )

        public_key = private_key.public_key()

        # Сериализация ключей
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return {
            "private_key": private_pem.decode('utf-8'),
            "public_key": public_pem.decode('utf-8')
        }

    def generate_session_key(self):
        """Генерация случайного ключа сессии"""
        return os.urandom(32)

    def _json_to_rsa_key(self, key_json: str):
        """Конвертирует ключ из JSON формата в RSA ключ"""
        import json
        from cryptography.hazmat.primitives.asymmetric import rsa

        key_data = json.loads(key_json)
        modulus = int(key_data['modulus'], 16)
        exponent = int(key_data['exponent'], 16)

        return rsa.RSAPublicNumbers(
            e=exponent,
            n=modulus
        ).public_key(self._backend)

    def encrypt_session_key(self, session_key: bytes, client_public_key_json: str):
        """Шифрование ключа сессии публичным ключом клиента"""
        try:
            # Пытаемся загрузить публичный ключ
            try:
                # Конвертируем JSON ключ в RSA ключ
                public_key = self._json_to_rsa_key(client_public_key_json)
            except Exception as e:
                print(f"Error loading public key: {str(e)}")
                raise

            # Шифруем ключ сессии
            encrypted_key = public_key.encrypt(
                session_key,
                padding.PKCS1v15()
            )

            result = base64.b64encode(encrypted_key).decode('utf-8')
            return result

        except Exception as e:
            print(f"Error in encrypt_session_key: {str(e)}")
            print(f"Error type: {type(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            raise

    def decrypt_with_session_key(self, encrypted_data: str, session_key: bytes):
        """Расшифровка данных с помощью ключа сессии"""
        try:
            # Декодируем base64
            try:
                encrypted_bytes = base64.b64decode(encrypted_data)
            except Exception as e:
                print(f"Base64 decoding failed: {str(e)}")
                raise

            # Получаем IV (первые 16 байт)
            if len(encrypted_bytes) < 16:
                raise ValueError(f"Encrypted data too short: {len(encrypted_bytes)} bytes")

            iv = encrypted_bytes[:16]
            ciphertext = encrypted_bytes[16:]
            print(f"IV length: {len(iv)}, ciphertext length: {len(ciphertext)}")

            # Создаем шифр
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.CBC(iv),
                backend=self._backend
            )

            # Расшифровываем
            try:
                decryptor = cipher.decryptor()
                padded_data = decryptor.update(ciphertext) + decryptor.finalize()
                print(f"Decryption successful, padded data length: {len(padded_data)}")
            except Exception as e:
                print(f"Decryption failed: {str(e)}")
                raise

            # Убираем паддинг
            if len(padded_data) == 0:
                raise ValueError("Decrypted data is empty")

            padding_length = padded_data[-1]
            if padding_length > len(padded_data):
                raise ValueError(f"Invalid padding length: {padding_length}")

            data = padded_data[:-padding_length]
            print(f"Padding removed, final data length: {len(data)}")

            # Декодируем UTF-8
            try:
                result = data.decode('utf-8')
                print(f"UTF-8 decoding successful, result: {result}")
                return result
            except Exception as e:
                print(f"UTF-8 decoding failed: {str(e)}")
                raise

        except Exception as e:
            print(f"Error in decrypt_with_session_key: {str(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            raise ValueError(f"Decryption failed: {str(e)}")

        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def encrypt_with_session_key(self, data: str, session_key: bytes):
        """Шифрование данных с помощью ключа сессии"""
        try:
            # Генерируем случайный IV
            iv = os.urandom(16)

            # Создаем шифр
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.CBC(iv),
                backend=self._backend
            )

            # Добавляем PKCS7 паддинг
            data_bytes = data.encode('utf-8')
            padding_length = 16 - (len(data_bytes) % 16)
            padded_data = data_bytes + bytes([padding_length] * padding_length)

            # Шифруем
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # Объединяем IV и шифротекст
            encrypted_data = iv + ciphertext

            return base64.b64encode(encrypted_data).decode('utf-8')

        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")