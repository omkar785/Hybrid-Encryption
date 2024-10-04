from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os

def aes_encrypt_file(file_path, aes_key):
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CFB, iv)

    with open(file_path, 'rb') as f:
        file_data = f.read()

    encrypted_data = iv + cipher.encrypt(file_data)
    return encrypted_data

def rsa_encrypt_aes_key(aes_key):
    with open("cloud/public.pem", "rb") as f:  
        public_key = RSA.import_key(f.read())
        rsa_cipher = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    return encrypted_aes_key

file_to_encrypt = "text.txt"
aes_key = get_random_bytes(32)

encrypted_file = aes_encrypt_file(file_to_encrypt, aes_key)
encrypted_aes_key = rsa_encrypt_aes_key(aes_key)


os.makedirs("cloud", exist_ok=True)

with open(os.path.join("cloud", "encrypted_file.bin"), "wb") as f:
    f.write(encrypted_file)

with open("encrypted_key.bin", "wb") as f:
    f.write(encrypted_aes_key)

print("File encrypted and stored in the cloud.")
