import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES
import base64
import json
import hashlib
import random
import string
import os
from passmanagerGui import *

# Global variable to store the key
key = ""

# Create main application window
root = tk.Tk()
root.title("Password Manager")

# Create notebook for tabs
notebook = ttk.Notebook(root)
notebook.pack(padx=10, pady=10)

# Create frames for each tab
frame_newpass = ttk.Frame(notebook)
frame_showpass = ttk.Frame(notebook)
frame_selectpass = ttk.Frame(notebook)
frame_updatepass = ttk.Frame(notebook)
frame_deletepass = ttk.Frame(notebook)

# Add frames to notebook with corresponding tab names
notebook.add(frame_newpass, text="New Password")
notebook.add(frame_showpass, text="Show Passwords")
notebook.add(frame_selectpass, text="Select Password")
notebook.add(frame_updatepass, text="Update Password")
notebook.add(frame_deletepass, text="Delete Password")

# Create labels and entry widgets for each tab
label_name = ttk.Label(frame_newpass, text="Name:")
entry_name = ttk.Entry(frame_newpass)
label_comment = ttk.Label(frame_newpass, text="Comment:")
entry_comment = ttk.Entry(frame_newpass)
label_key = ttk.Label(frame_newpass, text="Key:")
entry_key = ttk.Entry(frame_newpass, show="*")

# Pack widgets into the frame
label_name.pack(pady=5)
entry_name.pack(pady=5)
label_comment.pack(pady=5)
entry_comment.pack(pady=5)
label_key.pack(pady=5)
entry_key.pack(pady=5)


# Function to handle new password creation
def create_new_password():
    global key
    key = entry_key.get()

    if os.path.exists(passwords_file):
        decrypt_passwords_file(key)

    name = entry_name.get()
    comment = entry_comment.get()
    encrypted_password = save_password(name, comment, key)

    # Display pop-up message
    messagebox.showinfo("New Password Added", f"New Password added!\nEncrypted Password: {encrypted_password}")

    encrypt_passwords_file(key)


# Button to trigger new password creation
button_create_newpass = ttk.Button(frame_newpass, text="Create New Password", command=create_new_password)
button_create_newpass.pack(pady=10)


# Function to show passwords
def show_passwords():
    global key
    key = entry_showpass_key.get()

    decrypt_passwords_file(key)
    print('Showing Passwords..')

    # You can modify this part to display the passwords in a more user-friendly manner
    with open(passwords_file, "r") as file:
        for line in file:
            line = line.strip()  # Remove leading/trailing whitespaces
            if line:
                try:
                    entry = json.loads(line)
                    name = entry["name"]
                    decrypted_password = entry["password"]
                    comment = entry["comment"]
                    print(f"Name: {name}, Password: {decrypted_password}, Comment: {comment}")
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON: {e}")

    encrypt_passwords_file()



# Labels and entry widgets for showing passwords
label_showpass_key = ttk.Label(frame_showpass, text="Key:")
entry_showpass_key = ttk.Entry(frame_showpass, show="*")

# Pack widgets into the frame
label_showpass_key.pack(pady=5)
entry_showpass_key.pack(pady=5)

# Button to trigger show passwords
button_show_passwords = ttk.Button(frame_showpass, text="Show Passwords", command=show_passwords)
button_show_passwords.pack(pady=10)


# Function to select and display a specific password
def select_password():
    name = entry_selectpass_name.get()
    global key
    key = entry_selectpass_key.get()

    decrypt_passwords_file(key)
    print('Related data: ')

    with open(passwords_file, "r") as file:
        for line in file:
            entry = json.loads(line)
            if entry["name"] == name:
                print(f"Password: {entry['password']}, Comment: {entry['comment']}")
                break

    encrypt_passwords_file()


# Labels and entry widgets for selecting passwords
label_selectpass_name = ttk.Label(frame_selectpass, text="Name:")
entry_selectpass_name = ttk.Entry(frame_selectpass)
label_selectpass_key = ttk.Label(frame_selectpass, text="Key:")
entry_selectpass_key = ttk.Entry(frame_selectpass, show="*")

# Pack widgets into the frame
label_selectpass_name.pack(pady=5)
entry_selectpass_name.pack(pady=5)
label_selectpass_key.pack(pady=5)
entry_selectpass_key.pack(pady=5)

# Button to trigger select password
button_select_password = ttk.Button(frame_selectpass, text="Select Password", command=select_password)
button_select_password.pack(pady=10)


# Function to update a password
def update_password():
    name = entry_updatepass_name.get()
    global key
    key = entry_updatepass_key.get()

    decrypt_passwords_file(key)
    update_password(name)
    encrypt_passwords_file()


# Labels and entry widgets for updating passwords
label_updatepass_name = ttk.Label(frame_updatepass, text="Name:")
entry_updatepass_name = ttk.Entry(frame_updatepass)
label_updatepass_key = ttk.Label(frame_updatepass, text="Key:")
entry_updatepass_key = ttk.Entry(frame_updatepass, show="*")

# Pack widgets into the frame
label_updatepass_name.pack(pady=5)
entry_updatepass_name.pack(pady=5)
label_updatepass_key.pack(pady=5)
entry_updatepass_key.pack(pady=5)

# Button to trigger update password
button_update_password = ttk.Button(frame_updatepass, text="Update Password", command=update_password)
button_update_password.pack(pady=10)


# Function to delete a password
def delete_password():
    name = entry_deletepass_name.get()
    global key
    key = entry_deletepass_key.get()

    decrypt_passwords_file(key)
    delete_password(name)
    encrypt_passwords_file()


# Labels and entry widgets for deleting passwords
label_deletepass_name = ttk.Label(frame_deletepass, text="Name:")
entry_deletepass_name = ttk.Entry(frame_deletepass)
label_deletepass_key = ttk.Label(frame_deletepass, text="Key:")
entry_deletepass_key = ttk.Entry(frame_deletepass, show="*")

# Pack widgets into the frame
label_deletepass_name.pack(pady=5)
entry_deletepass_name.pack(pady=5)
label_deletepass_key.pack(pady=5)
entry_deletepass_key.pack(pady=5)

# Button to trigger delete password
button_delete_password = ttk.Button(frame_deletepass, text="Delete Password", command=delete_password)
button_delete_password.pack(pady=10)

# Run the Tkinter event loop
root.mainloop()
