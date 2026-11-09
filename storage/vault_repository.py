from .DataManager import DatabaseManager

class VaultRepository:
    
    def __init__(self, db_path: str):
        self.data_manager = DatabaseManager(db_path)
        self.data_manager.initialize_database()

    def save_metadata(
        self,
        salt_kek: bytes,
        encrypted_dek: bytes,
        nonce_kek: bytes,
        kdf_algorithm: str,
        kdf_parameters: dict[str, int],
    ) -> None:
        query = """
            INSERT INTO vault_metadata (
                id,
                salt_kek,
                encrypted_dek,
                nonce_kek,
                kdf_algorithm,
                time_cost,
                memory_cost,
                parallelism,
                hash_len
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        params = (
            1,
            salt_kek,
            encrypted_dek,
            nonce_kek,
            kdf_algorithm,
            kdf_parameters["time_cost"],
            kdf_parameters["memory_cost"],
            kdf_parameters["parallelism"],
            kdf_parameters["hash_len"],
        )

        self.data_manager.insert_data(query, params)
