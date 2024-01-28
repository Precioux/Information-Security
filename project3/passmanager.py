# Step 1: Import necessary libraries
import argparse
from Crypto.Cipher import AES
import base64
import json
import hashlib
import random
import string
global key

# Global variable to store the key
global key

# Step 2: Parse command-line arguments
parser = argparse.ArgumentParser(description="Password Manager")
parser.add_argument("--newpass", help="Create a new password", nargs=3)
parser.add_argument("--showpass",  help="Show saved passwords")
parser.add_argument("--sel", help="Select a password by name")
parser.add_argument("--update", help="Update a password", nargs=1)
parser.add_argument("--delete", help="Delete a password by name")
args = parser.parse_args()

def xor_encrypt(data, key):
    # Convert data and key to bytes
    data_bytes = data.encode()
    key_bytes = key.encode()

    # Repeat the key to match the length of data
    repeated_key = key_bytes * (len(data_bytes) // len(key_bytes)) + key_bytes[:len(data_bytes) % len(key_bytes)]

    # Perform XOR operation
    encrypted_bytes = bytes([data_byte ^ key_byte for data_byte, key_byte in zip(data_bytes, repeated_key)])

    # Encode the result as base64 for storage
    return base64.b64encode(encrypted_bytes).decode()

# Step 3: Define functions for encryption and decryption
def derive_key(password, salt=b'some_salt', iterations=100000, key_length=32):
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, key_length)
    return key

def encrypt(text, key):
    key = derive_key(key)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()


def decrypt(encrypted_text, key):
    data = base64.b64decode(encrypted_text.encode())
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()\



def xor_decrypt(data, key):
    encrypted_bytes = base64.b64decode(data)
    key_bytes = key.encode()

    # Repeat the key to match the length of data
    repeated_key = key_bytes * (len(encrypted_bytes) // len(key_bytes)) + key_bytes[
                                                                          :len(encrypted_bytes) % len(key_bytes)]

    # Perform XOR operation
    decrypted_bytes = bytes(
        [encrypted_byte ^ key_byte for encrypted_byte, key_byte in zip(encrypted_bytes, repeated_key)])

    # # Print debugging output
    # print("Encrypted Bytes:", encrypted_bytes)
    # print("Repeating Key:", repeated_key)
    # print("Decrypted Bytes:", decrypted_bytes)

    # Decode the result to get the plaintext
    decrypted_data = decrypted_bytes.decode()

    return decrypted_data


# Step 4: Manage passwords
passwords_file = "passwords.txt"


def generate_password(name, comment, key):
    # Generating a random salt
    salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    # Combining name, comment, key, and salt for password generation
    password_input = f"{name}_{comment}_{key}_{salt}"

    # You might want to implement a stronger password generation logic
    # Here, I'm just using the input directly, but you can use libraries
    # like 'secrets' to generate a more secure password.
    generated_password = hashlib.sha256(password_input.encode()).hexdigest()

    return generated_password


def save_password(name, comment, key):
    generated_password = generate_password(name, comment, key)
    encrypted_password = encrypt(generated_password,key)
    entry = {"name": name, "password": encrypted_password, "comment": comment, "key": key}
    with open(passwords_file, "a") as file:
        file.write(json.dumps(entry) + "\n")

    return encrypted_password


# Encrypt passwords.txt using XOR encryption
def encrypt_passwords_file():
    with open(passwords_file, "r") as file:
        plaintext = file.read()
    encrypted_data = xor_encrypt(plaintext, key)
    with open(passwords_file, "w") as file:
        file.write(encrypted_data)

# Decrypt passwords.txt using XOR decryption
def decrypt_passwords_file(key):
    with open(passwords_file, "r") as file:
        encrypted_data = file.read()
    decrypted_data = xor_decrypt(encrypted_data, key)

    # # Print decrypted content to the console
    # print("Decrypted Content:")
    # print(decrypted_data)

    # # Write decrypted content to another file for comparison (optional)
    # with open("decrypted_passwords.txt", "w") as decrypted_file:
    #     decrypted_file.write(decrypted_data)
    #
    with open(passwords_file, "w") as file:
        file.write(decrypted_data)



def show_passwords():
    with open(passwords_file, "r") as file:
        for line in file:
            entry = json.loads(line)
            name = entry["name"]
            decrypted_password = entry["password"]
            comment = entry["comment"]
            print(f"Name: {name}, Password: {decrypted_password}, Comment: {comment}")


def select_password(name):
    with open(passwords_file, "r") as file:
        for line in file:
            entry = json.loads(line)
            if entry["name"] == name:
                print(f"Password: {entry['password']}, Comment: {entry['comment']}")
                break


def update_password(name):
    global key  # You may want to handle the key in a more secure way
    with open(passwords_file, "r") as file:
        entries = [json.loads(line) for line in file]

    updated_entries = []

    for entry in entries:
        if entry["name"] == name:
            # Generate a new password for the existing entry
            new_generated_password = generate_password(entry["name"], entry["comment"], entry["key"])

            # Update the password field in the entry
            entry["password"] = new_generated_password

        updated_entries.append(entry)

    with open(passwords_file, "w") as file:
        for entry in updated_entries:
            file.write(json.dumps(entry) + "\n")

    print(f"Password for '{name}' updated!")


def delete_password(name):
    with open(passwords_file, "r") as file:
        entries = [json.loads(line) for line in file]
    with open(passwords_file, "w") as file:
        for entry in entries:
            if entry["name"] != name:
                file.write(json.dumps(entry) + "\n")


# Step 5: Handle command-line arguments
if args.newpass:
    name, comment, key = args.newpass
    enc = save_password(name, comment, key)
    print('New Password added!')
    print(f'Encrypted Password : {enc}')
    encrypt_passwords_file()

elif args.showpass:
    key = args.showpass
    decrypt_passwords_file(key)
    print('Showing Passwords..')
    show_passwords()
    encrypt_passwords_file()
elif args.sel:
    name = args.sel
    decrypt_passwords_file(key)
    print('Related data: ')
    select_password(name)
    encrypt_passwords_file()
elif args.update:
    name = args.update[0]
    update_password(name)
    encrypt_passwords_file()
elif args.delete:
    name = args.delete
    delete_password(name)
    encrypt_passwords_file()
    print('Deleted Successfully!')
else:
    print("Invalid command. Please use --help for usage information.")
