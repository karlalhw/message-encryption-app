from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

key = get_random_bytes(32)
print(f"Generated key (base64 encoded): {base64.b64encode(key).decode()}")

# Encrypt
message = input("Enter a message to encrypt: ").encode()
cipher = AES.new(key, AES.MODE_EAX)
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(message)
encoded_ciphertext = base64.b64encode(ciphertext).decode()
print(f"Encrypted message (base64): {encoded_ciphertext}")

# Decrypt
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
decrypted = cipher.decrypt(ciphertext)
try:
    cipher.verify(tag)
    print(f"Decrypted message: {decrypted.decode()}")
except ValueError:
    print("Decryption failed: Key or data is incorrect/corrupted")
