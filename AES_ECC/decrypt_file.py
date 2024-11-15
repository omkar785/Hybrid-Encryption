from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
import os

def aes_decrypt_file(encrypted_data, aes_key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return decrypted_data

# Function to verify passphrase by reading from passphrase.txt
def verify_passphrase():
    # Read the stored passphrase from the file
    try:
        with open("passphrase.txt", "r") as file:
            stored_passphrase = file.read().strip()  # Remove any extra whitespace/newlines

        # Prompt the user to enter their passphrase
        entered_passphrase = input("Enter passphrase: ")

        if entered_passphrase == stored_passphrase:
            return True
        else:
            print("Passphrase fails.")
            return False
    except FileNotFoundError:
        print("Passphrase file not found.")
        return False

# Check if passphrase is correct before proceeding
if verify_passphrase():
    # Load ECC private key and encrypted file data
    with open("encrypted_key.bin", "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())

    # Load public key to derive shared secret
    with open("cloud/public.pem", "rb") as f:
        public_key = load_pem_public_key(f.read(), backend=default_backend())

    # Generate shared key and derive AES key
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    # Decrypt the file
    with open("cloud/encrypted_file.bin", "rb") as f:
        encrypted_file_data = f.read()

    decrypted_file_data = aes_decrypt_file(encrypted_file_data, aes_key)

    # Save decrypted data
    with open("decrypted_file.txt", "wb") as f:
        f.write(decrypted_file_data)

    print("File decrypted successfully.")
else:
    print("Access denied due to incorrect passphrase.")
