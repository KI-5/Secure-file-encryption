from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os


#method to encrypt the file
def encrypt_file(input_file, output_file, passphrase):
    #generate key
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    #derive AES key
    key = kdf.derive(passphrase.encode())

    #generate iv
    iv = os.urandom(16)

    
    #encrypt the file
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Write the encrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(salt + iv + encryptor.tag + ciphertext)
    print(f"File '{input_file}' encrypted successfully!")



#method to decrypt the file
def decrypt_file(input_file, output_file, passphrase):
    with open(input_file, 'rb') as f:
        data = f.read()
    salt, iv, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]

    # Derive the AES key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())

    # Decrypt the file
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Write the decrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    print(f"File '{input_file}' decrypted successfully!")


import argparse

def main():
    parser = argparse.ArgumentParser(description="Secure File Encryption and Decryption Tool")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Action to perform")
    parser.add_argument("input", help="Input file path")
    parser.add_argument("output", help="Output file path")
    parser.add_argument("passphrase", help="Passphrase for encryption/decryption")

    args = parser.parse_args()

    if args.action == "encrypt":
        encrypt_file(args.input, args.output, args.passphrase)
    elif args.action == "decrypt":
        decrypt_file(args.input, args.output, args.passphrase)

if __name__ == "__main__":
    main()
