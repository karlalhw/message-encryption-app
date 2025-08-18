from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json
from datetime import datetime
import os
import fnmatch
import binascii

# Main menu function


def main_menu():
    print("Crypto App Menu:")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    print("3. Exit")
    while True:
        # Using try-except to catch the ValueError from int() and prevent a crash
        try:
            choice = int(input("Enter your choice (1-3): "))
            # Check if choice is in the range [1, 2, 3]
            if choice in [1, 2, 3]:
                return choice
            else:
                print("Please enter a number between 1 and 3.")
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 3.")


# Encrypts a wallet private key with AES-256 and saves to a unique JSON file

def encrypt_message():
    key = get_random_bytes(32)
    print(f"Generated key (base64 encoded): {base64.b64encode(key).decode()}")
    print("WARNING: Save this key securely (e.g., in a password manager), you will need it to decrypt.")
    # Ask for user input for encryption
    message = input("Enter a message to encrypt: ").encode()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message)
    encoded_ciphertext = base64.b64encode(ciphertext).decode()
    print(f"Encrypted message (base64): {encoded_ciphertext}")
    # Generate .JSON file name via datetime and save encrypted data
    filename = f"wallet_data{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.json"
    save_encrypted_data(nonce, ciphertext, tag, filename)
    return key, nonce, ciphertext, tag


# Save encrypted data function, excluding the key for security
def save_encrypted_data(nonce, ciphertext, tag, filename):
    try:
        data = {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode()
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
            print(f"Encrypted data saved to {filename}")
    except Exception as e:
        print(f"Error saving data to {filename}: {e}")


# Load encrypted data from a saved JSON file


def load_encrypted_data(filename):
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            nonce = base64.b64decode(data["nonce"])
            ciphertext = base64.b64decode(data["ciphertext"])
            tag = base64.b64decode(data["tag"])
            return nonce, ciphertext, tag
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        return None
    except (KeyError, json.JSONDecodeError):
        print(f"Error: File {filename} is invalid or corrupted.")
        return None


# Decrypt message function, requiring key input for decryption

def decrypt_message(nonce, ciphertext, tag):
    try:
        key_input = input("Enter the base64-encoded AES key: ")
        if not key_input:  # check for empty input
            print("Error: No key provided.")
            return
        key = base64.b64decode(key_input)
        if len(key) != 32:  # key must be 32 bytes
            print("Error: Invalid key length.")
            return
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"Decrypted message: {plaintext.decode()}")
    except binascii.Error:
        print("Error: Invalid base64-encoded key.")
    except ValueError:
        print("Error: Incorrect key or corrupted data.")


# List wallet files function

def list_wallet_files():
    return [f for f in os.listdir() if fnmatch.fnmatch(f, "wallet_data*.json")]

# Main loop function


def main():
    nonce, ciphertext, tag = None, None, None
    while True:
        choice = main_menu()
        if choice == 1:
            _, nonce, ciphertext, tag = encrypt_message()  # key is unused variable
        elif choice == 2:
            wallet_files = list_wallet_files()
            if not wallet_files:
                print("No wallet data files found.")
                continue
            print("Select a file to decrypt:")
            for i, file in enumerate(wallet_files, 1):
                print(f"{i}: {file}")
            try:
                file_choice = int(
                    input("Enter file number (1-{}):".format(len(wallet_files))))
                if 1 <= file_choice <= len(wallet_files):
                    result = load_encrypted_data(wallet_files[file_choice - 1])
                    if result:
                        nonce, ciphertext, tag = result
                        decrypt_message(nonce, ciphertext, tag)
                else:
                    print("Invalid file number.")
            except ValueError:
                print("Invalid input. Please enter a number.")

        elif choice == 3:
            print("Exiting Crypto App...")
            break


if __name__ == "__main__":
    main()
