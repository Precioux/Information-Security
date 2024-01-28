import argparse
from Crypto.Cipher import AES
import base64
import json
import hashlib
import random
import string
import os
import binascii  # Add this line to import the binascii module
from tkinter import *
from tkinter import messagebox
global key

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Password Manager")
parser.add_argument("--newpass", help="Create a new password", nargs=3)
parser.add_argument("--showpass", help="Show saved passwords")
parser.add_argument("--sel", help="Select a password by name", nargs=2)
parser.add_argument("--update", help="Update a password", nargs=2)
parser.add_argument("--delete", help="Delete a password by name", nargs=2)
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


def xor_decrypt(data, key):
    try:
        encrypted_bytes = base64.b64decode(data)
    except binascii.Error:
        print("Invalid base64-encoded string")
        return ""

    key_bytes = key.encode()

    # Repeat the key to match the length of data
    repeated_key = key_bytes * (len(encrypted_bytes) // len(key_bytes)) + key_bytes[
                                                                          :len(encrypted_bytes) % len(key_bytes)]

    # Perform XOR operation
    decrypted_bytes = bytes(
        [encrypted_byte ^ key_byte for encrypted_byte, key_byte in zip(encrypted_bytes, repeated_key)])

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
    generated_password = hashlib.sha256(password_input.encode()).hexdigest()

    return generated_password


def save_password(name, comment, key):
    generated_password = generate_password(name, comment, key)
    encrypted_password = encrypt(generated_password, key)
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
    global key
    with open(passwords_file, "r") as file:
        entries = [json.loads(line) for line in file]

    updated_entries = []

    for entry in entries:
        if entry["name"] == name:
            print(f'Previous Password: {entry["password"]}')
            # Generate a new password for the existing entry
            new_generated_password = generate_password(entry["name"], entry["comment"], entry["key"])

            # Update the password field in the entry
            entry["password"] =encrypt(new_generated_password, entry["key"])

            print(f'New Password: {entry["password"]}')

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


# Handle command-line arguments
if args.newpass:
    name, comment, key = args.newpass
    if os.path.exists(passwords_file):
        decrypt_passwords_file(key)
    enc = save_password(name, comment, key)
    encrypt_passwords_file()
    messagebox.showinfo("Password Manager", f"New Password added!\nEncrypted Password: {enc}")

elif args.showpass:
    key = args.showpass
    decrypt_passwords_file(key)
    show_passwords()
    encrypt_passwords_file()

elif args.sel:
    name, key = args.sel
    decrypt_passwords_file(key)
    select_password(name)
    encrypt_passwords_file()

elif args.update:
    name, key = args.update
    decrypt_passwords_file(key)
    update_password(name)
    encrypt_passwords_file()

elif args.delete:
    name, key = args.delete
    decrypt_passwords_file(key)
    delete_password(name)
    encrypt_passwords_file()
    messagebox.showinfo("Password Manager", "Password deleted successfully!")

else:
    # GUI
    # GUI
    def new_pass():
        name = name_entry.get()
        comment = comment_entry.get()
        key = key_entry.get()

        if not name or not comment or not key:
            messagebox.showerror("Error", "All fields must be filled!")
            return

        generated_password = generate_password(name, comment, key)
        encrypted_password = encrypt(generated_password, key)
        entry = {"name": name, "password": encrypted_password, "comment": comment, "key": key}

        with open(passwords_file, "a") as file:
            file.write(json.dumps(entry) + "\n")

        messagebox.showinfo("Password Manager", f"New Password added!\nEncrypted Password: {encrypted_password}")


    def show_pass():
        key = key_entry.get()
        print("Key obtained from entry:", key)

        decrypt_passwords_file(key)

        print("Key after decryption:", key)

        show_passwords()
        encrypt_passwords_file()


    def select_pass():
        key = key_entry.get()
        decrypt_passwords_file(key)
        select_password(name_entry.get())
        encrypt_passwords_file()


    def update_pass():
        key = key_entry.get()
        decrypt_passwords_file(key)
        update_password(name_entry.get())
        encrypt_passwords_file()
        messagebox.showinfo("Password Manager", "Password updated successfully!")


    def delete_pass():
        key = key_entry.get()
        decrypt_passwords_file(key)
        delete_password(name_entry.get())
        encrypt_passwords_file()
        messagebox.showinfo("Password Manager", "Password deleted successfully!")


    window = Tk()
    window.title("Password Manager")

    name_label = Label(window, text="Name:")
    name_label.grid(row=0, column=0, padx=10, pady=5, sticky=W)

    name_entry = Entry(window)
    name_entry.grid(row=0, column=1, padx=10, pady=5, sticky=W)

    comment_label = Label(window, text="Comment:")
    comment_label.grid(row=1, column=0, padx=10, pady=5, sticky=W)

    comment_entry = Entry(window)
    comment_entry.grid(row=1, column=1, padx=10, pady=5, sticky=W)

    key_label = Label(window, text="Key:")
    key_label.grid(row=2, column=0, padx=10, pady=5, sticky=W)

    key_entry = Entry(window)
    key_entry.grid(row=2, column=1, padx=10, pady=5, sticky=W)

    new_button = Button(window, text="New Password", command=new_pass)
    new_button.grid(row=3, column=0, padx=10, pady=10, sticky=W)

    show_button = Button(window, text="Show Passwords", command=show_pass)
    show_button.grid(row=3, column=1, padx=10, pady=10, sticky=W)

    select_button = Button(window, text="Select Password", command=select_pass)
    select_button.grid(row=4, column=0, padx=10, pady=10, sticky=W)

    update_button = Button(window, text="Update Password", command=update_pass)
    update_button.grid(row=4, column=1, padx=10, pady=10, sticky=W)

    delete_button = Button(window, text="Delete Password", command=delete_pass)
    delete_button.grid(row=5, column=0, padx=10, pady=10, sticky=W)

    window.mainloop()
