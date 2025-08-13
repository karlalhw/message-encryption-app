from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

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


# Encrypt message function


def encrypt_message():
    key = get_random_bytes(32)
    print(f"Generated key (base64 encoded): {base64.b64encode(key).decode()}")
    # Ask for user input for encryption
    message = input("Enter a message to encrypt: ").encode()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message)
    encoded_ciphertext = base64.b64encode(ciphertext).decode()
    print(f"Encrypted message (base64): {encoded_ciphertext}")
    return key, nonce, ciphertext, tag

# Decrypt message function


def decrypt_message(key, nonce, ciphertext, tag):

    # Decrypt
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print(f"Decrypted message: {decrypted.decode()}")
    except ValueError:
        print("Decryption failed: Key or data is incorrect/corrupted")


# Main loop function


def main():
    key, nonce, ciphertext, tag = None, None, None, None
    while True:
        choice = main_menu()
        if choice == 1:
            key, nonce, ciphertext, tag = encrypt_message()
        elif choice == 2:
            if key is None:
                print("No encrypted message available. Please encrypt a message first.")
            else:
                decrypt_message(key, nonce, ciphertext, tag)
        elif choice == 3:
            print("Exiting Crypto App...")
            break


if __name__ == "__main__":
    main()
