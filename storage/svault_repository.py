import dataclasses
import os
import secrets
import shutil
from pathlib import Path
from cryptography.exceptions import InvalidTag
 
from crypto.cryptation import Cryptation

from crypto.cryptation import Cryptation
from storage.svault_payload import payload_to_bytes, bytes_to_payload
from model.models import VaultHeader, VaultPayload
from storage.svault_format import (
    NONCE_LEN,
    header_size,
    pack_header,
    unpack_header,
)

TAG_LEN = 16 # Tag AES-GCM

class SvaultRepository:
    def __init__(self, path:str | Path):
        self.path = Path(path)
        self.tmp_path = self.path.with_name(self.path.name + ".tmp")
        self.bak_path = self.path.with_name(self.path.name + ".bak")
        self.cryptation = Cryptation()

    def vault_exists(self) -> bool:
        return self.path.exists()

    def create(self, header: VaultHeader, payload: VaultPayload, dek: bytes) -> VaultHeader:
        if self.vault_exists():
            raise FileExistsError(f'O cofre já existe: {self.path}')

        self.path.parent.mkdir(parents=True, exist_ok=True)
        return self.save(header, payload, dek)

    def save(self, header: VaultHeader, payload: VaultPayload, dek: bytes) -> VaultHeader:
        plaintext = payload_to_bytes(payload)
        new_header = dataclasses.replace(
            header,
            payload_nonce= secrets.token_bytes(NONCE_LEN),
            payload_len=len(plaintext) + TAG_LEN,
        )
        header_bytes = pack_header(new_header)

        encrypted = self.cryptation.encrypt(
            dek,
            plaintext,
            aad=header_bytes,
            nonce=new_header.payload_nonce
        )

        self._atomic_write(header_bytes + encrypted.ciphertext)
        return new_header

    def read_header(self) -> VaultHeader:
        return unpack_header(self.path.read_bytes())


    def load(self, dek: bytes) -> tuple[VaultHeader, VaultPayload]:
        data = self.path.read_bytes()
        header = unpack_header(data)
 
        header_len = header_size(len(header.salt))
        if len(data) != header_len + header.payload_len:
            raise ValueError("tamanho do arquivo não confere com o header")
 
        aad = data[:header_len]
        ciphertext = data[header_len:]
 
        try:
            plaintext = self.cryptation.decrypt(
                dek, header.payload_nonce, ciphertext, aad=aad
            )
        except InvalidTag as exc:
            raise ValueError("dados do cofre corrompidos ou adulterados") from exc
 
        return header, bytes_to_payload(plaintext)
 
    def _atomic_write(self, data: bytes) -> None:
        with open(self.tmp_path, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
 
        if self.path.exists():
            shutil.copy2(self.path, self.bak_path)
 
        os.replace(self.tmp_path, self.path)
 

    
    