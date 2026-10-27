
import sqlite3
from datetime import datetime, timezone

from config import DATABASE_PATH


def get_connection():
    """Open a SQLite connection with foreign-key enforcement."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(DATABASE_PATH))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    """Create the application tables if they do not exist."""
    schema = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
            CHECK (role IN ('user', 'admin')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        storage_name TEXT NOT NULL UNIQUE,
        original_name TEXT NOT NULL,
        owner_id INTEGER NOT NULL,
        size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
        uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users(id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS download_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash TEXT NOT NULL UNIQUE,
        file_id INTEGER NOT NULL,
        created_by INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (file_id) REFERENCES files(id)
            ON DELETE CASCADE,
        FOREIGN KEY (created_by) REFERENCES users(id)
            ON DELETE CASCADE
    );
    """

    with get_connection() as connection:
        connection.executescript(schema)


def create_user(username: str, password_hash: str) -> int:
    """Create a regular user and return their ID."""
    username = username.strip().lower()

    if not username or len(username) > 50:
        raise ValueError("Username must contain 1 to 50 characters.")

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, 'user')
            """,
            (username, password_hash),
        )
        return cursor.lastrowid


def get_user_by_username(username: str):
    """Find a user by username."""
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username.strip().lower(),),
        ).fetchone()


def get_user_by_id(user_id: int):
    """Find a user by ID."""
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


def create_file_record(
    storage_name: str,
    original_name: str,
    owner_id: int,
    size_bytes: int,
) -> int:
    """Register an encrypted file and its owner."""
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO files (
                storage_name, original_name, owner_id, size_bytes
            )
            VALUES (?, ?, ?, ?)
            """,
            (storage_name, original_name, owner_id, size_bytes),
        )
        return cursor.lastrowid


def get_file_by_id(file_id: int):
    """Retrieve a file record by its ID."""
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM files WHERE id = ?",
            (file_id,),
        ).fetchone()


def get_files_for_user(user_id: int, is_admin: bool = False):
    """List owned files, or all files for an administrator."""
    with get_connection() as connection:
        if is_admin:
            return connection.execute(
                """
                SELECT files.*, users.username AS owner_username
                FROM files
                JOIN users ON users.id = files.owner_id
                ORDER BY files.uploaded_at DESC
                """
            ).fetchall()

        return connection.execute(
            """
            SELECT files.*, users.username AS owner_username
            FROM files
            JOIN users ON users.id = files.owner_id
            WHERE files.owner_id = ?
            ORDER BY files.uploaded_at DESC
            """,
            (user_id,),
        ).fetchall()


def delete_file_record(
    file_id: int,
    owner_id: int,
    is_admin: bool = False,
) -> bool:
    """Delete a file record only for its owner or an administrator."""
    with get_connection() as connection:
        if is_admin:
            cursor = connection.execute(
                "DELETE FROM files WHERE id = ?",
                (file_id,),
            )
        else:
            cursor = connection.execute(
                "DELETE FROM files WHERE id = ? AND owner_id = ?",
                (file_id, owner_id),
            )

        return cursor.rowcount > 0


def create_download_link(
    token_hash: str,
    file_id: int,
    created_by: int,
    expires_at: str,
) -> int:
    """Create a temporary download-link record."""
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO download_links (
                token_hash, file_id, created_by, expires_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (token_hash, file_id, created_by, expires_at),
        )
        return cursor.lastrowid


def get_download_link_by_hash(token_hash: str):
    """Find a link and its associated file using the token hash."""
    with get_connection() as connection:
        return connection.execute(
            """
            SELECT download_links.*,
                   files.storage_name,
                   files.original_name,
                   files.owner_id,
                   files.size_bytes
            FROM download_links
            JOIN files ON files.id = download_links.file_id
            WHERE download_links.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()


def mark_download_link_used(link_id: int) -> bool:
    """Atomically consume a link only if it is unused and unexpired."""
    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE download_links
            SET used_at = ?
            WHERE id = ?
              AND used_at IS NULL
              AND expires_at > ?
            """,
            (now, link_id, now),
        )
        return cursor.rowcount == 1


if __name__ == "__main__":
    init_db()
    print(f"Database tables initialized at: {DATABASE_PATH}")
