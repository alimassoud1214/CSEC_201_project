from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def generate_rsa_keys():
    key = RSA.generate(2048)

    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return public_key, private_key


def generate_session_key():
    return get_random_bytes(16)
    
    
if __name__ == "__main__":
    public_key, private_key = generate_rsa_keys()
    session_key = generate_session_key()

    print("Public Key:")
    print(public_key.decode())

    print("\nPrivate Key:")
    print(private_key.decode())

    print("\nSession Key:")
    print(session_key)
