# Helper functions for the Caesar cipher.
# The cipher shifts each character by a fixed amount.

def caesar_encrypt(text, shift=3):
    result = ""

    for char in text:
        result += chr((ord(char) + shift) % 256)

    return result


def caesar_decrypt(text, shift=3):
    result = ""

    for char in text:
        result += chr((ord(char) - shift) % 256)

    return result
