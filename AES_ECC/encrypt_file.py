from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
import os

def aes_encrypt_file(file_path, aes_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        file_data = f.read()

    encrypted_data = iv + encryptor.update(file_data) + encryptor.finalize()
    return encrypted_data

# Load ECC public key
with open("cloud/public.pem", "rb") as f:
    public_key = load_pem_public_key(f.read(), backend=default_backend())

# Generate AES key and encrypt file
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
shared_key = private_key.exchange(ec.ECDH(), public_key)

# Derive AES key from the shared key using HKDF
aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key)

file_to_encrypt = "text.txt"
encrypted_file = aes_encrypt_file(file_to_encrypt, aes_key)

# Save the encrypted file
os.makedirs("cloud", exist_ok=True)
with open(os.path.join("cloud", "encrypted_file.bin"), "wb") as f:
    f.write(encrypted_file)

# Save the encrypted AES key (in practice, you would send the ECC private key)
with open("encrypted_key.bin", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

print("File encrypted and stored in the cloud.")
