import os, base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# =====================================================
# HASHING WITH SALT – PASSWORD STORAGE
# Algorithm: PBKDF2 + SHA-256 + Random Salt
# Satisfies: Hashing with Salt
# =====================================================
def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000  # High iteration count for brute-force resistance
    )
    return base64.b64encode(kdf.derive(password.encode()))


def verify_password(password, salt, stored_hash):
    """
    Password verification during login
    Used in Single-Factor Authentication
    """
    return hash_password(password, salt) == stored_hash


# =====================================================
# KEY GENERATION – RSA
# Generates RSA-2048 key pair
# Satisfies: Encryption – Key Exchange / Key Generation
# =====================================================
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key, private_key.public_key()


# =====================================================
# ENCRYPTION – AES
# AES-256 in CFB mode with random IV
# Satisfies: Encryption & Decryption
# =====================================================
def encrypt_data(data, key):
    iv = os.urandom(16)  # Random IV for semantic security
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()


# =====================================================
# DIGITAL SIGNATURE
# RSA + SHA-256 + PSS Padding
# Ensures integrity & authenticity
# Satisfies: Digital Signature using Hash
# =====================================================
def sign_data(data, private_key):
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# =====================================================
# DIGITAL SIGNATURE VERIFICATION
# RSA + SHA-256 + PSS Padding
# Ensures integrity & authenticity
# Satisfies: Digital Signature using Hash
# Used when QR code is scanned (Future Scope)
# =====================================================
def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
