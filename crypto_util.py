# Helper functions for the Caesar cipher (shifting characters)
def caesar_encrypt(text, shift=3):
    result = ""
    for char in text:
        # Move the ASCII character forward by the shift value
        result += chr((ord(char) + shift) % 256)
    return result

def caesar_decrypt(text, shift=3):
    result = ""
    for char in text:
        # Shift back to get the original message
        result += chr((ord(char) - shift) % 256)
    return result

# Simple RSA simulation to pass encrypted keys during setup
def simulate_rsa_encrypt(pub_key, session_key):
    return "ENC_" + session_key + "_" + pub_key

def simulate_rsa_decrypt(priv_key, enc_session_key):
    # Strip away the key wrapper to get the raw session key back
    if enc_session_key.startswith("ENC_"):
        parts = enc_session_key.split("_")
        return parts[1]
    return enc_session_key