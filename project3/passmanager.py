# Step 1: Import necessary libraries
import argparse
from Crypto.Cipher import AES
import base64
import json
import hashlib

# Step 2: Parse command-line arguments
parser = argparse.ArgumentParser(description="Password Manager")
parser.add_argument("--newpass", help="Create a new password", nargs=4)
parser.add_argument("--showpass", action="store_true", help="Show saved passwords")
parser.add_argument("--sel", help="Select a password by name")
parser.add_argument("--update", help="Update a password", nargs=2)
parser.add_argument("--del", help="Delete a password by name")
args = parser.parse_args()

# Step 3: Define functions for encryption and decryption
def derive_key(password, salt=b'some_salt', iterations=100000, key_length=32):
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, key_length)
    return key

def encrypt(text, key):
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


def save_password(name, password, comment, key):
    encrypted_password = encrypt(password, key)
    with open(passwords_file, "a") as file:
        entry = {"name": name, "password": encrypted_password, "comment": comment}
        file.write(json.dumps(entry) + "\n")
    return  encrypted_password


def show_passwords(key):
    with open(passwords_file, "r") as file:
        for line in file:
            entry = json.loads(line)
            name = entry["name"]
            decrypted_password = decrypt(entry["password"], key)
            comment = entry["comment"]
            print(f"Name: {name}, Password: {decrypted_password}, Comment: {comment}")


def select_password(name, key):
    with open(passwords_file, "r") as file:
        for line in file:
            entry = json.loads(line)
            if entry["name"] == name:
                decrypted_password = decrypt(entry["password"], key)
                comment = entry["comment"]
                print(f"Name: {name}, Password: {decrypted_password}, Comment: {comment}")
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
    name, comment, password, key = args.newpass
    new_key = derive_key(key)
    # print(f'name: {name}\ncomment: {comment}\nkey: {key}\npassword: {password}\n')
    encrypted_password = save_password(name, password, comment, new_key)
    print('New Password added!')
    print(f'Encrypted Password: {encrypted_password}')
elif args.showpass:
    key = input("Enter your simple password: ")
    key = derive_key(key)
    show_passwords(key)
elif args.sel:
    name, key = args.sel, input("Enter your simple password: ")
    key = derive_key(key)
    select_password(name, key)
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
