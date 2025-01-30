# crypto_utils.py

import base64
import secrets
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import hashlib
import bcrypt


def derive_key_from_password(password: str, salt: bytes = None, iterations: int = 100000) -> tuple[Fernet, bytes]:
    """
    Derives a key from a given password using PBKDF2-HMAC-SHA256 and returns a Fernet key.
    If no salt is provided, a new one will be generated.

    :param password: The user's password to derive the key from
    :param salt: The salt to use for the key derivation. If None, a new salt is generated
    :param iterations: The number of iterations for the key derivation function (default: 100,000)
    :return: A tuple containing the Fernet encryption key and the salt
    """
    if salt is None:
        salt = secrets.token_bytes(16)  # Generate a 16-byte salt

    # PBKDF2-HMAC-SHA256 key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256 encryption
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )

    # Derive the key and encode it as a Fernet-compatible base64 string
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    return Fernet(key), salt


def encrypt_data(fernet_key: Fernet, plaintext: str) -> bytes:
    """
    Encrypts a plaintext string using the provided Fernet key.

    :param fernet_key: The Fernet encryption key
    :param plaintext: The data to be encrypted
    :return: The encrypted data as bytes
    """
    return fernet_key.encrypt(plaintext.encode())


def decrypt_data(fernet_key: Fernet, encrypted_data: bytes) -> str:
    """
    Decrypts encrypted data using the provided Fernet key.

    :param fernet_key: The Fernet encryption key
    :param encrypted_data: The data to be decrypted
    :return: The decrypted plaintext
    :raises: ValueError if the decryption fails due to an invalid key or corrupted data
    """
    try:
        return fernet_key.decrypt(encrypted_data).decode()
    except InvalidToken:
        raise ValueError("Decryption failed: Invalid key or corrupted data")


def generate_salt(length: int = 16) -> bytes:
    """
    Generates a cryptographically secure random salt.

    :param length: The length of the salt in bytes (default: 16)
    :return: A cryptographically secure random salt
    """
    return secrets.token_bytes(length)


def get_hashed_password(plain_text_password):
    password = bytes(plain_text_password, "utf-8")
    return bcrypt.hashpw(password, bcrypt.gensalt())



def check_password(plain_text_password, hashed_password):
    return bcrypt.checkpw(plain_text_password, hashed_password)



"""

EXAMPLE USEAGE


from crypto_utils import derive_key_from_password, encrypt_data, decrypt_data, generate_salt


# User's master password
m_password = "user_master_password"

# Deriving a key and generating a salt
fernet_key, salt = derive_key_from_password(m_password)

# Encrypt a password
plaintext_password = "my_secure_password"
encrypted_password = encrypt_data(fernet_key, plaintext_password)

# Later, decrypt the password
decrypted_password = decrypt_data(fernet_key, encrypted_password)

print(f"Original password: {plaintext_password}")
print(f"Encrypted password: {encrypted_password}")
print(f"Decrypted password: {decrypted_password}")

"""
