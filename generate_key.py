import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

passphrase = input("Set your passcode")
private_key = RSA.generate(2048)
public_key = private_key.publickey()

passphrase_bytes = passphrase.encode()
passphrase_length = len(passphrase_bytes)

private_key_bytes = private_key.export_key(format='DER')
modified_key_bytes = bytearray(private_key_bytes)

for i in range(len(modified_key_bytes)):
    modified_key_bytes[i] ^= passphrase_bytes[i % passphrase_length]

with open("modified_private.pem", "wb") as f:
    f.write(bytes(modified_key_bytes))

os.makedirs("cloud", exist_ok=True)

with open(os.path.join("cloud", "public.pem"), "wb") as f:
    f.write(public_key.export_key())

print("Modified RSA key and public key saved successfully.")
