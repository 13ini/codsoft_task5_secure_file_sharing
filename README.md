
# SecureShare — Secure File Sharing System

A Python and Flask web application that provides authenticated file uploads and downloads, encryption at rest, role-based access control, and expiring temporary download links.

## Features

- User registration and login
- Secure password hashing
- File encryption before storage using Fernet symmetric encryption
- Authenticated file uploads and downloads
- Role-based access control for regular users and administrators
- Temporary download links with configurable expiry
- Single-use temporary download links
- CSRF protection for forms
- File-extension validation and a 10 MiB upload limit
- SQLite database for user, file, and download-link metadata
- Environment-based secret configuration

## Technology Stack

- Python 3.11+
- Flask
- Flask-Login
- Flask-WTF
- Cryptography
- SQLite
- HTML and CSS

## Project Structure

```text
CODSOFT_TASK5/
├── src/
│   ├── app.py
│   ├── auth.py
│   ├── config.py
│   ├── database.py
│   ├── encryption.py
│   └── models.py
├── templates/
├── static/
├── screenshots/
├── tests/
├── docs/
├── reports/
├── storage/
├── instance/
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.11 or later
- pip
- A modern web browser

## Installation on Windows

Open PowerShell in the project root.

### 1. Create a virtual environment

```powershell
py -3.11 -m venv .venv
```

If the environment already exists, you can skip this command.

### 2. Activate the environment

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root. Configure these two variables with fresh, valid secret values:

```dotenv
FLASK_SECRET_KEY=your-generated-flask-secret
FILE_ENCRYPTION_KEY=your-generated-fernet-key
```

Do not use the placeholder values from `.env.example` in a running application.

Generate valid values locally without printing them in the terminal:

```powershell
@'
from pathlib import Path
import secrets
from cryptography.fernet import Fernet

Path(".env").write_text(
    f"FLASK_SECRET_KEY={secrets.token_hex(32)}\n"
    f"FILE_ENCRYPTION_KEY={Fernet.generate_key().decode('ascii')}\n",
    encoding="utf-8"
)
print("Environment secrets generated.")
'@ | python -
```

**Important:** Keep `.env` private. Back up the encryption key securely. If you lose or replace the key, previously encrypted files may no longer be recoverable.

### 5. Initialize the database

```powershell
python .\src\database.py
```

### 6. Start the application

```powershell
python .\src\app.py
```

Open the local URL shown in the terminal in your browser.

## Using SecureShare

1. Register a user account.
2. Log in with your credentials.
3. Upload a supported file.
4. Create a temporary download link and choose an expiry period.
5. Use the link before it expires. Temporary links are designed for one successful download.

Supported extensions: `.pdf`, `.txt`, `.png`, `.jpg`, `.jpeg`, `.docx`.

Maximum upload size: 10 MiB.

## Security Notes

- Passwords are stored as password hashes, not plaintext.
- Uploaded file contents are encrypted before being written to storage.
- Regular users can access their own files; administrators can access all files.
- Temporary-link tokens are stored as SHA-256 hashes in the database.
- Forms use CSRF protection.
- Download responses include cache-control and content-sniffing protections.
- The local database and stored files should not be committed to Git.
- The built-in Flask development server is intended for local development, not production deployment.

## Testing

Run Python syntax checks from the project root:

```powershell
python -m compileall .\src
```

Perform manual tests for registration, login, upload, download, file access permissions, invalid file types, oversized files, temporary-link expiry, and single-use behavior.

## Disclaimer

This project is developed for educational and authorized testing purposes. Use only files and systems you are authorized to access.
