# generator.py
import string
import random
from passmanagerPlus import *

def generate_passwords():
    # Set the common parameters
    name = "generated"
    comment = "auto-generated password"
    key = "0000"

    # Create a list to store passwords
    passwords = []

    # Generate 1000 passwords
    for i in range(0, 1000):
        name = f'generated-{i}'
        comment = f'auto-generated password-{i}'
        generated_password = generate_password(name, comment, key)
        encrypted_password = encrypt(generated_password, key)
        passwords.append(encrypted_password)
        print(f'Password{i} generated!')
    print('Generation is Done!')

    # Write passwords to the test.txt file
    with open("testPlus.txt", "w") as file:
        for password in passwords:
            print(f'writing password: {password}')
            file.write(f"{password}\n")
    print('Done')

if __name__ == "__main__":
    generate_passwords()
