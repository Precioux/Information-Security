from cryptography.fernet import Fernet
import os

def generate_key():
    key = Fernet.generate_key()
    print(f"Generated key: {key.decode()}")
    return key

def load_key():
    return open("secret.key", "rb").read()

def save_key(key):
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def encrypt(filename, key):
    fernet = Fernet(key)

    with open(filename, "rb") as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    encrypted_filename = f"{filename}.encrypted"
    with open(encrypted_filename, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

def decrypt(filename, key):
    fernet = Fernet(key)

    with open(filename, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    decrypted_filename = 'decrypted-'+filename[:-len(".encrypted")]
    with open(decrypted_filename, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

def main():
    try:
        mode = int(input("Enter the mode (1 for encryption, 2 for decryption): "))

        if mode == 1:  # Encryption
            key_option = int(input("Enter 1 to generate a key, or 2 to use an existing key: "))

            if key_option == 1:
                key = generate_key()
                save_key(key)
            elif key_option == 2:
                key = load_key()
            else:
                print("Invalid option for key. Please enter 1 or 2.")
                return

            filename = input("Enter the file path for encryption: ")
            encrypt(filename, key)
            print("Encryption successful.")

        elif mode == 2:  # Decryption
            key = input("Enter the decryption key: ")
            filename = input("Enter the file path for decryption: ")
            decrypt(filename, key)
            print("Decryption successful.")

        else:
            print("Invalid mode. Please enter 1 or 2.")
    except ValueError:
        print("Invalid input. Please enter valid integers.")

if __name__ == "__main__":
    main()
