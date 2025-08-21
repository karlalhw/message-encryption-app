# crypto-app
A command-line Python app for creating and saving encrypted messages (via AES-256) as JSON files that can be decrypted by a key.

Features:
- Encrypts user messages with AES-256-EAX, generating a random 32-byte key
- Saves encrypted data (nonce, ciphertext, tag) to JSON files named with timestamps (e.g., message2025-8-22_1253.json)
- Allows decrpytion using the user-provided key (base64-encoded)
- Features a menu with input validation and error handling
- Uses pycryptodome for encryption and fnmatch for file listing

## Usage
Run the app with:
```bash
python crypto_app.py