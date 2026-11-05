import os
import hashlib

senha = "SenhaFoda123".encode('utf-8')

salt_hex = os.urandom(32).hex()
salt_bytes = bytes.fromhex(salt_hex)

hash_complet = hashlib.pbkdf2_hmac('sha256', senha, salt_bytes, 600000)
hash_final = hash_complet.hex()

print(senha)
print(salt_hex)
print(salt_bytes)
print(hash_final)