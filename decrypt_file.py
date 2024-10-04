from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

def rsa_decrypt_aes_key(encrypted_aes_key, passphrase):
    with open("modified_private.pem", "rb") as f:
        modified_key_bytes = f.read()

    passphrase_bytes = passphrase.encode()
    passphrase_length = len(passphrase_bytes)

    private_key_bytes = bytearray(modified_key_bytes)
    for i in range(len(private_key_bytes)):
        private_key_bytes[i] ^= passphrase_bytes[i % passphrase_length]

    private_key = RSA.import_key(bytes(private_key_bytes))
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    return aes_key

def aes_decrypt_file(encrypted_data, aes_key):
    iv = encrypted_data[:16]
    cipher = AES.new(aes_key, AES.MODE_CFB, iv)
    decrypted_data = cipher.decrypt(encrypted_data[16:])
    return decrypted_data

with open("encrypted_key.bin", "rb") as f:
    encrypted_aes_key = f.read()

user_passphrase = input("Enter your secret passphrase: ")
aes_key = rsa_decrypt_aes_key(encrypted_aes_key, user_passphrase)

with open("cloud/encrypted_file.bin", "rb") as f:
    encrypted_file_data = f.read()

decrypted_file_data = aes_decrypt_file(encrypted_file_data, aes_key)

with open("decrypted_file.txt", "wb") as f:
    f.write(decrypted_file_data)

print("File decrypted successfully.")
