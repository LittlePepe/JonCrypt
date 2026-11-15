from storage.svault_repository import SvaultRepository
from model.models import VaultHeader, VaultPayload, CredentialEntry
import time
import dataclasses

class credentialManager:
    def __init__(self, dek: bytes, header: VaultHeader, payload: VaultPayload, repository: SvaultRepository):
        self.dek = dek
        self.header = header
        self.payload = payload
        self.repository = repository

    def add_credential(self, link:str, password: str) -> CredentialEntry:
        credential = CredentialEntry(
            id=self.payload.next_id,
            link=link,
            password=password,
            created_at=int(time.time()),
            updated_at=None
        )

        self.payload.entries.append(credential)
        self.payload.next_id += 1

        self._save()
        
        return credential

    def get_credential(self, credential_id: int) -> CredentialEntry | None:
        for credential in self.payload.entries:
            if credential.id == credential_id:
                return credential
        return None

    def update_password(self, credential_id: int, new_password: str) -> CredentialEntry:
        for index, credential in enumerate(self.payload.entries):
            if credential.id == credential_id:
                updated = dataclasses.replace(
                    credential,
                    password=new_password,
                    updated_at=int(time.time()),
                )
                self.payload.entries[index] = updated
                self._save()
                return updated
        raise KeyError(f"credencial {credential_id} não encontrada")
 
    def remove_credential(self, credential_id: int) -> None:
        before = len(self.payload.entries)
        self.payload.entries = [
            c for c in self.payload.entries if c.id != credential_id
        ]
        if len(self.payload.entries) == before:
            raise KeyError(f"credencial {credential_id} não encontrada")
        self._save()
 
    def _save(self) -> None:
        self.header = self.repository.save(self.header, self.payload, self.dek)
 
