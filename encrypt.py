from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Generate a random key
key = get_random_bytes(16)

# Encrypt
def encrypt(text):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + ciphertext).decode('utf-8')

# Decrypt
def decrypt(encrypted_text):
    data = base64.b64decode(encrypted_text)
    nonce = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

message = "This is a secret message"
encrypted = encrypt(message)
print("Encrypted:", encrypted)
print("Decrypted:", decrypt(encrypted))
