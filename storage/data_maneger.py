import sqlite3
from pathlib import Path

class DatabaseManager:
    def __init__(self, db_name: str):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()


    def initialize_database(self):

        schema_path = Path(__file__).with_name("schema.sql")
        with schema_path.open("r", encoding="utf-8") as file:
            schema = file.read()
            
        self.cursor.executescript(schema)

        metadata_columns = {
            row[1]
            for row in self.cursor.execute("PRAGMA table_info(vault_metadata)").fetchall()
        }
        if "hash_len" not in metadata_columns:
            self.cursor.execute(
                "ALTER TABLE vault_metadata "
                "ADD COLUMN hash_len INTEGER NOT NULL DEFAULT 32"
            )

        self.conn.commit()

    def insert_data(self, query: str, params: tuple):
        self.cursor.execute(query, params)
        self.conn.commit()

    def fetch_data(self, query: str, params: tuple = ()):
        self.cursor.execute(query, params)
        return self.cursor.fetchall()

    def close(self):
        self.conn.close()

    
