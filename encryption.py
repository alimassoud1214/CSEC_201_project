from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keys():
    key = RSA.generate(2048)

    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return public_key, private_key


def generate_session_key():
    return get_random_bytes(16)

def encrypt_session_key(public_key, session_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)

    encrypted_key = cipher_rsa.encrypt(session_key)

    return encrypted_key


def decrypt_session_key(private_key, encrypted_session_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)

    decrypted_key = cipher_rsa.decrypt(encrypted_session_key)

    return decrypted_key
    
    
if __name__ == "__main__":
    public_key, private_key = generate_rsa_keys()
    session_key = generate_session_key()

    encrypted_key = encrypt_session_key(public_key, session_key)
    decrypted_key = decrypt_session_key(private_key, encrypted_key)

    print("Public Key:")
    print(public_key.decode())

    print("\nPrivate Key:")
    print(private_key.decode())

    print("\nSession Key:")
    print(session_key)

    print("\nEncrypted Session Key:")
    print(encrypted_key)

    print("\nDecrypted Session Key:")
    print(decrypted_key)

    print("\nKeys Match:")
    print(session_key == decrypted_key)