import hashlib
import bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import itertools

# Hash a password using SHA-256
def sha256_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Hash a password using bcrypt
def bcrypt_hash(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Check password strength
def check_password_policy(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not any(char.isupper() for char in password):
        return "Password must include at least one uppercase letter."
    if not any(char.isdigit() for char in password):
        return "Password must include at least one number."
    return "Password is strong."

# Encrypt a password using AES
def aes_encrypt(password, key):
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(password.encode()) + encryptor.finalize()
    return iv + encrypted

# Decrypt a password using AES
def aes_decrypt(encrypted, key):
    iv = encrypted[:16]
    encrypted_password = encrypted[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(encrypted_password) + decryptor.finalize()).decode()

# Dictionary attack
def dictionary_attack(target_hash, dictionary_file):
    with open(dictionary_file, 'r') as file:
        for word in file:
            guess = word.strip()
            if hashlib.sha256(guess.encode()).hexdigest() == target_hash:
                return guess
    return None

# Brute force attack
def brute_force_attack(target_hash, charset, max_length):
    for length in range(1, max_length + 1):
        for guess_tuple in itertools.product(charset, repeat=length):
            guess = ''.join(guess_tuple)
            if hashlib.sha256(guess.encode()).hexdigest() == target_hash:
                return guess
    return None

# Main function
def main():
    print("Welcome to the Password Cracking and Protection Toolkit\n")

    # Password input and policy check
    password = input("Enter a password: ")
    policy_check = check_password_policy(password)
    if policy_check != "Password is strong.":
        print(policy_check)
        return

    # Hashing demonstration
    sha256_hashed = sha256_hash(password)
    bcrypt_hashed = bcrypt_hash(password)
    print(f"\nSHA-256 Hashed Password: {sha256_hashed}")
    print(f"Bcrypt Hashed Password: {bcrypt_hashed.decode()}")

    # Encryption demonstration
    key = os.urandom(32)  # Generate AES key
    encrypted = aes_encrypt(password, key)
    decrypted = aes_decrypt(encrypted, key)
    print(f"\nEncrypted Password (AES): {encrypted}")
    print(f"Decrypted Password (AES): {decrypted}")

    # Password cracking
    print("\nCracking Demonstration:")
    target_hash = sha256_hashed
    dictionary_file = "dictionary.txt"

    # Dictionary attack
    cracked_password = dictionary_attack(target_hash, dictionary_file)
    if cracked_password:
        print(f"Password found using dictionary attack: {cracked_password}")
    else:
        print("Password not found in dictionary.")

    # Brute force attack
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    cracked_password = brute_force_attack(target_hash, charset, max_length=4)
    if cracked_password:
        print(f"Password found using brute force: {cracked_password}")
    else:
        print("Password not found using brute force.")

if __name__ == "__main__":
    main()
