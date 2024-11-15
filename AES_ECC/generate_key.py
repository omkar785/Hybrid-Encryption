from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

# Generate ECC private key
private_key = ec.generate_private_key(ec.SECP256R1())

# Encrypt and save the private key with a passphrase
passphrase = input("Set your passphrase: ")
with open("passphrase.txt", "w") as file:
    file.write(passphrase)
passphrase = passphrase.encode()
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
)

# Save the private key to a file
with open("modified_private.pem", "wb") as f:
    f.write(private_key_bytes)

# Generate and save the public key
public_key = private_key.public_key()
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

os.makedirs("cloud", exist_ok=True)
with open(os.path.join("cloud", "public.pem"), "wb") as f:
    f.write(public_key_bytes)

print("ECC key pair generated and saved successfully.")
