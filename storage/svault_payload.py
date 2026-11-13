from dataclasses import asdict
import json
from model.models import CredentialEntry, VaultPayload

SCHEMA_VERSION = 1

def payload_to_bytes(payload: VaultPayload, credential: CredentialEntry):
    payload.entries.append(credential)
    payload.next_id += 1

    dict_payload = asdict(payload)

    return json.dumps(dict_payload, ensure_ascii=False).encode("utf-8")

def bytes_to_payload(payload_bytes):
    try:
        data = json.loads(payload_bytes.decode("utf-8"))

        if not isinstance(data, dict):
            raise ValueError("Payload error")

        schema = data.get("schema_version")
        next_id = data.get("next_id")
        entries = data.get("entries")

        if schema != SCHEMA_VERSION:
            raise ValueError("Schema error")

        if not isinstance(next_id, int) or next_id < 1:
            raise ValueError("next_id inválido.")

        if not isinstance(entries, list):
            raise ValueError("Entries inválido.")

        credentials = [
            CredentialEntry(**credential) 
            for credential in entries
        ]

        return VaultPayload(
            schema_version=schema,
            next_id=next_id,
            entries=credentials
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise ValueError(f'Falha ao reconstruir o payload: {error}') from error
        
