from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import argon2
import secrets

dados = b"TesteMaluco"
senha_mestre = b"SenhaFoda123"

# Chave Mestre - KEK
salt_kek = secrets.token_bytes(16)

kek = argon2.low_level.hash_secret_raw(
    secret=senha_mestre,
    salt=salt_kek,
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=argon2.low_level.Type.ID
)

nonce_kek = secrets.token_bytes(12)
cipher_kek = AESGCM(kek)
print(f'Chave KEK: {cipher_kek} \n')

# DEK
dek = secrets.token_bytes(32)
print(f'Chave DEK Puro: {dek.hex()}\n')

# Criptografar chave DEK com KEK
wrapped_dek = cipher_kek.encrypt(
    nonce_kek,
    dek,
    None
)
print(f'Chave DEK Cript: {wrapped_dek.hex()} \n')

decript_dek = cipher_kek.decrypt(
    nonce_kek,
    wrapped_dek,
    None
)
print(f'Chave DEK Descript: {decript_dek.hex()} \n')

cipher_dek = AESGCM(decript_dek)
nonce_dek = secrets.token_bytes(12)

ciphertext = cipher_dek.encrypt(
    nonce_dek,
    dados,
    None
)

print(f'Dados criptografados: {ciphertext.hex()} \n')

decript_text = cipher_dek.decrypt(
    nonce_dek,
    ciphertext,
    None
)

print(f'Dados descriptografados: {decript_text.hex()} \n')
print(f'Dados: {decript_text.decode('utf-8')}')

