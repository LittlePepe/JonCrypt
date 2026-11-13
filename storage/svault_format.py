import struct
from model.models import VaultHeader, KdfParams

# Constantes do formato
MAGIC = b"SVLT"
FORMAT_MAJOR = 1
FORMAT_MINOR = 0
KDF_ARGON2ID = 1
CIPHER_AES256GCM = 1
NONCE_LEN = 12
WRAPPED_DEK_LEN = 48  # DEK (32) + tag GCM (16)
 
# Layout binário
PREFIX_FORMAT = ">4sHHHIBIIBBB"
SUFFIX_FORMAT = ">B12s48s12sQ"
PREFIX_SIZE = struct.calcsize(PREFIX_FORMAT)  # 26
SUFFIX_SIZE = struct.calcsize(SUFFIX_FORMAT)  # 81
 
# Limites de validação
TIME_COST_MIN = 1
TIME_COST_MAX = 10
MEMORY_COST_MIN = 8192        # 8 MiB
MEMORY_COST_MAX = 1048576     # 1 GiB
PARALLELISM_MIN = 1
PARALLELISM_MAX = 16
SALT_LEN_MIN = 16
SALT_LEN_MAX = 64
REQUIRED_HASH_LEN = 32

def _check_range(name: str, value: int, minimum: int, maximum: int) -> None:
    if not minimum <= value <= maximum:
        raise ValueError(
            f"{name}={value} fora do intervalo permitido ({minimum}–{maximum})"
        )
 
 
def _validate_header(header: VaultHeader) -> None:
    # Versão
    if header.format_major == 0:
        raise ValueError("format_major inválido (0)")
    if header.format_major > FORMAT_MAJOR:
        raise UnicodeTranslateError(
            f"cofre na versão {header.format_major}.{header.format_minor}; "
            f"esta versão do JonCrypt suporta até {FORMAT_MAJOR}.x"
        )
 
    # Algoritmos
    if header.kdf_id != KDF_ARGON2ID:
        raise ValueError(f"kdf_id desconhecido: {header.kdf_id}")
    if header.cipher_id != CIPHER_AES256GCM:
        raise ValueError(f"cipher_id desconhecido: {header.cipher_id}")
 
    # Parâmetros do Argon2id
    params = header.kdf_params
    _check_range("time_cost", params.time_cost, TIME_COST_MIN, TIME_COST_MAX)
    _check_range("memory_cost", params.memory_cost, MEMORY_COST_MIN, MEMORY_COST_MAX)
    _check_range("parallelism", params.parallelism, PARALLELISM_MIN, PARALLELISM_MAX)
    if params.hash_len != REQUIRED_HASH_LEN:
        raise ValueError(
            f"hash_len deve ser {REQUIRED_HASH_LEN}, recebido {params.hash_len}"
        )
 
    # Tamanhos dos campos de bytes
    _check_range("salt_len", len(header.salt), SALT_LEN_MIN, SALT_LEN_MAX)
    if len(header.dek_nonce) != NONCE_LEN:
        raise ValueError(f"dek_nonce deve ter {NONCE_LEN} bytes")
    if len(header.payload_nonce) != NONCE_LEN:
        raise ValueError(f"payload_nonce deve ter {NONCE_LEN} bytes")
    if len(header.wrapped_dek) != WRAPPED_DEK_LEN:
        raise ValueError(f"wrapped_dek deve ter {WRAPPED_DEK_LEN} bytes")
 
    if header.payload_len < 0:
        raise ValueError("payload_len não pode ser negativo")
    
def header_size(salt_len: int) -> int:
    return PREFIX_SIZE + salt_len + SUFFIX_SIZE

def kdf_section(header: VaultHeader) -> bytes:
    return pack_header(header)[:PREFIX_SIZE + len(header.salt)]

def pack_header(header: VaultHeader) -> bytes:
    salt_len = len(header.salt)
    header_len = header_size(salt_len)

    prefix = struct.pack(
        PREFIX_FORMAT,
        MAGIC,
        header.format_major,
        header.format_minor,
        header.flags,
        header_len,
        header.kdf_id,
        header.kdf_params.time_cost,
        header.kdf_params.memory_cost,
        header.kdf_params.parallelism,
        header.kdf_params.hash_len,
        salt_len,
    )

    suffix = struct.pack(
        SUFFIX_FORMAT,
        header.cipher_id,
        header.dek_nonce,
        header.wrapped_dek,
        header.payload_nonce,
        header.payload_len,
    )

    return prefix + header.salt + suffix

def unpack_header(data: bytes) -> VaultHeader:

    if len(data) < PREFIX_SIZE:
        raise ValueError("arquivo curto demais para ser um cofre .svault")
    if data[:len(MAGIC)] != MAGIC:
        raise ValueError("não é um cofre JonCrypt (magic inválido)")
 
    # Prefixo
    (
        _magic,
        format_major,
        format_minor,
        flags,
        header_len,
        kdf_id,
        time_cost,
        memory_cost,
        parallelism,
        hash_len,
        salt_len,
    ) = struct.unpack_from(PREFIX_FORMAT, data, 0)
 
    _check_range("salt_len", salt_len, SALT_LEN_MIN, SALT_LEN_MAX)
    if header_len != header_size(salt_len):
        raise ValueError("header_len inconsistente com salt_len")
    if len(data) < header_len:
        raise ValueError("arquivo truncado: header incompleto")
 
    salt_start = PREFIX_SIZE
    salt_end = PREFIX_SIZE + salt_len
    salt = data[salt_start:salt_end]
 
    # Sufixo
    (
        cipher_id,
        dek_nonce,
        wrapped_dek,
        payload_nonce,
        payload_len,
    ) = struct.unpack_from(SUFFIX_FORMAT, data, salt_end)
 
    header = VaultHeader(
        format_major=format_major,
        format_minor=format_minor,
        flags=flags,
        kdf_id=kdf_id,
        kdf_params=KdfParams(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
        ),
        salt=salt,
        cipher_id=cipher_id,
        dek_nonce=dek_nonce,
        wrapped_dek=wrapped_dek,
        payload_nonce=payload_nonce,
        payload_len=payload_len,
    )
 
    _validate_header(header)
    return header
 