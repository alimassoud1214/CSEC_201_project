import base64

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES


# =========================
# RSA
# =========================

def generate_rsa_keys():
    """
    Generate a 2048-bit RSA public/private key pair.
    """
    key = RSA.generate(2048)

    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return public_key, private_key


def generate_session_key():
    """
    Generate a 128-bit AES session key.
    """
    return get_random_bytes(16)


def encrypt_session_key(public_key, session_key):
    """
    Encrypt the session key using RSA-OAEP.
    """
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)

    return cipher_rsa.encrypt(session_key)


def decrypt_session_key(private_key, encrypted_session_key):
    """
    Decrypt the session key using RSA-OAEP.
    """
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)

    return cipher_rsa.decrypt(encrypted_session_key)


# =========================
# AES-GCM
# =========================

def aes_encrypt(text, session_key):
    """
    Encrypt text using AES-GCM.

    Returns:
        Base64(nonce + authentication tag + ciphertext)
    """
    cipher = AES.new(session_key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(
        text.encode("utf-8")
    )

    encrypted_data = cipher.nonce + tag + ciphertext

    return base64.b64encode(encrypted_data).decode("utf-8")


def aes_decrypt(encoded_data, session_key):
    """
    Decrypt AES-GCM data produced by aes_encrypt().
    """
    encrypted_data = base64.b64decode(encoded_data)

    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    cipher = AES.new(
        session_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    plaintext = cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    return plaintext.decode("utf-8")


# =========================
# TEST
# =========================

if __name__ == "__main__":

    public_key, private_key = generate_rsa_keys()

    session_key = generate_session_key()

    encrypted_key = encrypt_session_key(
        public_key,
        session_key
    )

    decrypted_key = decrypt_session_key(
        private_key,
        encrypted_key
    )

    print("RSA Keys Match:", session_key == decrypted_key)

    message = "RFMP encryption test"

    encrypted_message = aes_encrypt(
        message,
        session_key
    )

    decrypted_message = aes_decrypt(
        encrypted_message,
        session_key
    )

    print("AES Message Match:", message == decrypted_message)
