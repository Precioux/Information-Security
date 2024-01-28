# Step 1: Import necessary libraries
import argparse
from Crypto.Cipher import AES
import base64
import json
import hashlib
import random
import string

# Step 2: Parse command-line arguments
parser = argparse.ArgumentParser(description="Password Manager")
parser.add_argument("--newpass", help="Create a new password", nargs=3)
parser.add_argument("--showpass", action="store_true", help="Show saved passwords")
parser.add_argument("--sel", help="Select a password by name")
parser.add_argument("--update", help="Update a password", nargs=2)
parser.add_argument("--delete", help="Delete a password by name")
args = parser.parse_args()


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
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


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
    encrypted_password = encrypt(generated_password, key)
    with open(passwords_file, "a") as file:
        entry = {"name": name, "password": encrypted_password, "comment": comment}
        file.write(json.dumps(entry) + "\n")
    return encrypted_password


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


def update_password(name, new_password, key):
    with open(passwords_file, "r") as file:
        entries = [json.loads(line) for line in file]
    with open(passwords_file, "w") as file:
        for entry in entries:
            if entry["name"] == name:
                entry["password"] = encrypt(new_password, key)
            file.write(json.dumps(entry) + "\n")


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
    encrypted_password = save_password(name, comment, key)
    print('New Password added!')
    print(f'Encrypted Password: {encrypted_password}')
elif args.showpass:
    print('Showing Passwords..')
    show_passwords()
elif args.sel:
    name = args.sel
    print('Related data: ')
    select_password(name)
elif args.update:
    name, key = args.update
    new_password = input("Enter the new password: ")
    key = derive_key(key)
    update_password(name, new_password, key)
elif args.delete:
    name = args.delete
    delete_password(name)
else:
    print("Invalid command. Please use --help for usage information.")
