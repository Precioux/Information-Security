import random
import string
import time


def calculate_possibilities(password, char_set):
    length = len(password)

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

    found = False
    num_iterations = 0

    while not found:
        num_iterations += 1
        random_guess = ''.join(random.choice(characters) for _ in range(length))
        print(f"Trying password: {random_guess}")

        if random_guess == password:
            found = True
            print(f"Found the password: {password}")

    end_time = time.time()

    calculation_time = (end_time - start_time) / num_iterations

    password_count = len(characters) ** length

    return password_count, calculation_time


def calculate_possibilities_first_char(length, first_char, char_set, password):
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

    found = False
    num_iterations = 0

    while not found:
        num_iterations += 1
        random_password = first_char + ''.join(random.choice(characters) for _ in range(length - 1))
        print(f"Trying password: {random_password}")

        if random_password == password:
            found = True
            print(f"Found the password: {password}")

    end_time = time.time()

    calculation_time = (end_time - start_time) / num_iterations

    password_count = len(characters) ** (length - 1)

    return password_count, calculation_time


def calculate_possibilities_partial(length, k, partial, char_set, password):
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

    found = False
    num_iterations = 0

    while not found:
        num_iterations += 1
        random_password = partial + ''.join(random.choice(characters) for _ in range(length - k))
        print(f"Trying password: {random_password}")

        if random_password == password:
            found = True
            print(f"Found the password: {password}")

    end_time = time.time()

    calculation_time = (end_time - start_time) / num_iterations

    password_count = len(characters) ** (length - k)

    return password_count, calculation_time


def standard_mode(password):
    char_set = int(input("Enter the character set (1 for numbers, 2 for lowercase letters, 3 for both): "))

    possibilities, calculation_time = calculate_possibilities(password, char_set)

    if possibilities is not None:
        print(f"Number of password possibilities: {possibilities}")
        print(f"Estimated calculation time: {calculation_time:.10f} seconds")


def first_char_mode(password):
    length = len(password)
    first_char = password[0]
    char_set = int(input("Enter the character set (1 for numbers, 2 for lowercase letters, 3 for both): "))

    possibilities, calculation_time = calculate_possibilities_first_char(length, first_char, char_set, password)

    if possibilities is not None:
        print(f"Number of password possibilities: {possibilities}")
        print(f"Estimated calculation time: {calculation_time:.10f} seconds")


def partial_mode(password):
    length = len(password)
    k = int(input("Enter the value of k (number of characters to reveal): "))
    partial = password[:k]
    char_set = int(input("Enter the character set (1 for numbers, 2 for lowercase letters, 3 for both): "))

    possibilities, calculation_time = calculate_possibilities_partial(length, k, partial, char_set, password)

    if possibilities is not None:
        print(f"Number of password possibilities: {possibilities}")
        print(f"Estimated calculation time: {calculation_time:.10f} seconds")


def main():
    password = input("Enter the password: ")

    try:
        mode = int(input("Enter the mode (1 for standard, 2 for first char, 3 for partial): "))

        if mode == 1:
            standard_mode(password)
        elif mode == 2:
            first_char_mode(password)
        elif mode == 3:
            partial_mode(password)
        else:
            print("Invalid mode. Please enter 1, 2, or 3.")
    except ValueError:
        print("Invalid input. Please enter a valid integer for the mode.")


if __name__ == "__main__":
    main()
