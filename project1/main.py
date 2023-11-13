import random
import string
import time


def calculate_possibilities(length, char_set, num_iterations=10000):
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

    for _ in range(num_iterations):
        random_password = ''.join(random.choice(characters) for _ in range(length))

    end_time = time.time()

    calculation_time = (end_time - start_time) / num_iterations

    password_count = len(characters) ** length

    return password_count, calculation_time


def standard_mode():
    try:
        password_length = int(input("Enter the length of the password: "))
        char_set = int(input("Enter the character set (1 for numbers, 2 for lowercase letters, 3 for both): "))

        if password_length <= 0:
            print("Please enter a positive integer for the password length.")
            return

        possibilities, calculation_time = calculate_possibilities(password_length, char_set, num_iterations=10000)

        if possibilities is not None:
            print(f"Number of password possibilities: {possibilities}")
            print(f"Estimated calculation time: {calculation_time:.10f} seconds")
    except ValueError:
        print("Invalid input. Please enter valid integers.")


def calculate_possibilities_first_char(length, first_char, char_set, num_iterations=10000):
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

    for _ in range(num_iterations):
        random_password = first_char + ''.join(random.choice(characters) for _ in range(length - 1))

    end_time = time.time()

    calculation_time = (end_time - start_time) / num_iterations

    password_count = len(characters) ** (length - 1)

    return password_count, calculation_time


def first_char_mode():
    try:
        password_length = int(input("Enter the length of the password: "))
        first_char = input("Enter the first character of the password: ")
        char_set = int(input("Enter the character set (1 for numbers, 2 for lowercase letters, 3 for both): "))

        if password_length <= 1:
            print("Please enter a password length greater than 1.")
            return

        possibilities, calculation_time = calculate_possibilities_first_char(password_length, first_char, char_set,
                                                                             num_iterations=10000)

        if possibilities is not None:
            print(f"Number of password possibilities: {possibilities}")
            print(f"Estimated calculation time: {calculation_time:.10f} seconds")
    except ValueError:
        print("Invalid input. Please enter valid integers.")


def calculate_possibilities_partial(length, k, partial, char_set, num_iterations=10000):
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

    for _ in range(num_iterations):
        random_password = partial + ''.join(random.choice(characters) for _ in range(length - k))

    end_time = time.time()

    calculation_time = (end_time - start_time) / num_iterations

    password_count = len(characters) ** (length - k)

    return password_count, calculation_time


def partial_mode():
    try:
        password_length = int(input("Enter the length of the password: "))
        k = int(input("Enter the value of k (number of characters to reveal): "))
        partial = input(f"Enter {k} characters of the password: ")
        char_set = int(input("Enter the character set (1 for numbers, 2 for lowercase letters, 3 for both): "))

        if k <= 0 or k >= password_length:
            print("Please enter a valid value for k.")
            return

        possibilities, calculation_time = calculate_possibilities_partial(password_length, k, partial, char_set,
                                                                         num_iterations=10000)

        if possibilities is not None:
            print(f"Number of password possibilities: {possibilities}")
            print(f"Estimated calculation time: {calculation_time:.10f} seconds")
    except ValueError:
        print("Invalid input. Please enter valid integers.")


def main():
    try:
        mode = int(input("Enter the mode (1 for standard, 2 for first char, 3 for partial): "))

        if mode == 1:
            standard_mode()
        elif mode == 2:
            first_char_mode()
        elif mode == 3:
            partial_mode()
        else:
            print("Invalid mode. Please enter 1, 2, or 3.")
    except ValueError:
        print("Invalid input. Please enter a valid integer for the mode.")


if __name__ == "__main__":
    main()
