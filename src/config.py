
import os
from pathlib import Path

from dotenv import load_dotenv
from cryptography.fernet import Fernet

# Project directories
BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = BASE_DIR / "storage"
DATABASE_PATH = BASE_DIR / "instance" / "secure_share.db"

# Load local environment variables from the project root
load_dotenv(BASE_DIR / ".env")

# Require secrets instead of silently using insecure defaults
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
FILE_ENCRYPTION_KEY = os.getenv("FILE_ENCRYPTION_KEY")

if not FLASK_SECRET_KEY:
    raise RuntimeError(
        "FLASK_SECRET_KEY is missing. Configure it in the project .env file."
    )

if not FILE_ENCRYPTION_KEY:
    raise RuntimeError(
        "FILE_ENCRYPTION_KEY is missing. Configure it in the project .env file."
    )

try:
    Fernet(FILE_ENCRYPTION_KEY.encode("ascii"))
except (ValueError, TypeError, UnicodeEncodeError) as exc:
    raise RuntimeError(
        "FILE_ENCRYPTION_KEY is invalid. Generate a valid Fernet key."
    ) from exc

# Upload limits and allowed file extensions
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MiB
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg", ".docx"}
