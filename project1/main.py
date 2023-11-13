import random
import string
import time

def get_standard_password(length, char_set):
    if char_set == 1:
        characters = string.digits  # Only numbers
    elif char_set == 2:
        characters = string.ascii_lowercase  # Only lowercase letters
    elif char_set == 3:
        characters = string.digits + string.ascii_lowercase  # Numbers and lowercase letters
    else:
        print("Invalid character set. Please enter 1, 2, or 3.")
        return None

    start_time = time.time()
    password_count = len(characters) ** length
    end_time = time.time()

    calculation_time = end_time - start_time

    return password_count, calculation_time

def main():
    try:
        password_length = int(input("Enter the length of the password: "))
        char_set = int(input("Enter the character set (1 for numbers, 2 for lowercase letters, 3 for both): "))

        if password_length <= 0:
            print("Please enter a positive integer for the password length.")
            return

        password_count, calculation_time = get_standard_password(password_length, char_set)

        if password_count is not None:
            print(f"Number of password possibilities: {password_count}")
            print(f"Estimated calculation time: {calculation_time:.6f} seconds")
    except ValueError:
        print("Invalid input. Please enter valid integers.")

if __name__ == "__main__":
    main()
