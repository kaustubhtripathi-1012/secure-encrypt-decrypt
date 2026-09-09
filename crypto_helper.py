import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derive_key(password: str, secret_key: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from the user's password and secret key.
    """
    combined = f"{password}{secret_key}".encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(combined)

def encrypt_message(message: str, password: str, secret_key: str) -> dict:
    """
    Encrypt message using AES-GCM. Returns a dictionary of Base64 strings.
    """
    salt = os.urandom(16)
    key = derive_key(password, secret_key, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    
    # Encrypt. The returned bytearray has format: ciphertext + 16-byte tag
    encrypted_data = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
    ciphertext = encrypted_data[:-16]
    tag = encrypted_data[-16:]
    
    combined_bytes = salt + nonce + ciphertext
    
    return {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8'),
        'combined_ciphertext': base64.b64encode(combined_bytes).decode('utf-8')
    }

def decrypt_message(ciphertext_b64: str, nonce_b64: str = None, tag_b64: str = None, salt_b64: str = None, password: str = None, secret_key: str = None) -> str:
    """
    Decrypt the message. Returns the original string, or None if authentication fails.
    Supports both separate parameters and combined ciphertext (containing salt and nonce).
    """
    try:
        if nonce_b64 is None or salt_b64 is None:
            # Combined format: salt (16 bytes) + nonce (12 bytes) + ciphertext
            combined = base64.b64decode(ciphertext_b64)
            salt = combined[:16]
            nonce = combined[16:28]
            ciphertext = combined[28:]
        else:
            ciphertext = base64.b64decode(ciphertext_b64)
            nonce = base64.b64decode(nonce_b64)
            salt = base64.b64decode(salt_b64)
            
        tag = base64.b64decode(tag_b64)
        
        key = derive_key(password, secret_key, salt)
        aesgcm = AESGCM(key)
        
        # AESGCM.decrypt expects ciphertext + tag
        data_to_decrypt = ciphertext + tag
        decrypted_bytes = aesgcm.decrypt(nonce, data_to_decrypt, None)
        return decrypted_bytes.decode('utf-8')
    except Exception:
        # Decryption fails if the key is wrong (verification tag mismatch) or data is invalid
        return None

