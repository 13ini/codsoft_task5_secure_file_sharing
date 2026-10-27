
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

from auth import hash_password, verify_password
from config import (
    ALLOWED_EXTENSIONS,
    FLASK_SECRET_KEY,
    MAX_CONTENT_LENGTH,
    STORAGE_DIR,
)
from database import (
    create_download_link,
    create_file_record,
    create_user,
    get_download_link_by_hash,
    get_file_by_id,
    get_files_for_user,
    get_user_by_username,
    init_db,
    mark_download_link_used,
)
from encryption import decrypt_file, encrypt_file
from models import User


BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

app.config["SECRET_KEY"] = FLASK_SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

CSRFProtect(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

STORAGE_DIR.mkdir(parents=True, exist_ok=True)
init_db()


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


def allowed_file(filename):
    return (
        bool(filename)
        and bool(Path(filename).suffix)
        and Path(filename).suffix.lower() in ALLOWED_EXTENSIONS
    )


def is_admin():
    return (
        current_user.is_authenticated
        and current_user.role == "admin"
    )


def can_access_file(record):
    return (
        current_user.is_authenticated
        and (
            is_admin()
            or record["owner_id"] == int(current_user.id)
        )
    )


def get_safe_storage_path(storage_name):
    root = STORAGE_DIR.resolve()
    candidate = (root / storage_name).resolve()

    try:
        candidate.relative_to(root)
    except ValueError:
        abort(404)

    return candidate


def secure_download_response(storage_name, original_name):
    storage_path = get_safe_storage_path(storage_name)

    if not storage_path.is_file():
        abort(404)

    try:
        encrypted_data = storage_path.read_bytes()
        decrypted_data = decrypt_file(encrypted_data)
    except (OSError, ValueError):
        app.logger.exception("File read or decryption failed.")
        abort(500)

    response = send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=original_name,
        mimetype="application/octet-stream",
        max_age=0,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        if not username or len(username) > 50:
            flash("Username must contain 1 to 50 characters.", "error")
            return render_template("register.html"), 400

        if len(password) < 12:
            flash("Password must contain at least 12 characters.", "error")
            return render_template("register.html"), 400

        if get_user_by_username(username):
            flash("That username is already registered.", "error")
            return render_template("register.html"), 409

        try:
            create_user(username, hash_password(password))
        except sqlite3.IntegrityError:
            flash("That username is already registered.", "error")
            return render_template("register.html"), 409

        flash("Account created. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        record = get_user_by_username(username)

        if record and verify_password(record["password_hash"], password):
            login_user(User(record))
            flash("You have logged in successfully.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    files = get_files_for_user(
        int(current_user.id),
        is_admin=is_admin(),
    )
    return render_template("dashboard.html", files=files)


@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    uploaded = request.files.get("file")

    if uploaded is None or not uploaded.filename:
        flash("Choose a file to upload.", "error")
        return redirect(url_for("dashboard"))

    original_name = secure_filename(uploaded.filename)

    if not original_name or not allowed_file(original_name):
        flash("This file type is not allowed.", "error")
        return redirect(url_for("dashboard"))

    file_data = uploaded.stream.read(MAX_CONTENT_LENGTH + 1)

    if not file_data:
        flash("The selected file is empty.", "error")
        return redirect(url_for("dashboard"))

    if len(file_data) > MAX_CONTENT_LENGTH:
        flash("File exceeds the 10 MiB limit.", "error")
        return redirect(url_for("dashboard"))

    storage_name = secrets.token_hex(24) + ".enc"
    storage_path = get_safe_storage_path(storage_name)

    try:
        encrypted_data = encrypt_file(file_data)

        with storage_path.open("xb") as destination:
            destination.write(encrypted_data)

        try:
            create_file_record(
                storage_name=storage_name,
                original_name=original_name,
                owner_id=int(current_user.id),
                size_bytes=len(file_data),
            )
        except Exception:
            storage_path.unlink(missing_ok=True)
            raise

    except Exception:
        app.logger.exception("File upload failed.")
        flash("Upload failed. Please try again.", "error")
        return redirect(url_for("dashboard"))

    flash("File uploaded and encrypted successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/download/<int:file_id>")
@login_required
def download_file(file_id):
    record = get_file_by_id(file_id)

    if record is None:
        abort(404)

    if not can_access_file(record):
        abort(403)

    return secure_download_response(
        record["storage_name"],
        record["original_name"],
    )


@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
def create_share_link(file_id):
    record = get_file_by_id(file_id)

    if record is None:
        abort(404)

    if not can_access_file(record):
        abort(403)

    allowed_durations = {
        "5": 5,
        "60": 60,
        "1440": 1440,
    }

    duration_value = request.form.get("duration", "60")

    if duration_value not in allowed_durations:
        flash("Choose a valid link expiry duration.", "error")
        return redirect(url_for("dashboard"))

    duration_minutes = allowed_durations[duration_value]
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(minutes=duration_minutes)
    ).isoformat(timespec="seconds")

    try:
        create_download_link(
            token_hash=token_hash,
            file_id=file_id,
            created_by=int(current_user.id),
            expires_at=expires_at,
        )
    except Exception:
        app.logger.exception("Temporary link creation failed.")
        flash("Could not create the temporary link.", "error")
        return redirect(url_for("dashboard"))

    share_url = url_for(
        "temporary_download",
        token=token,
        _external=True,
    )

    flash(
        f"Temporary link (expires in {duration_minutes} minutes): {share_url}",
        "success",
    )
    return redirect(url_for("dashboard"))


@app.route("/temporary-download/<token>", methods=["GET"])
def temporary_download(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    record = get_download_link_by_hash(token_hash)

    if record is None:
        return "This download link is invalid or no longer available.", 404

    if record["used_at"] is not None:
        return "This download link has already been used.", 410

    try:
        expiry = datetime.fromisoformat(record["expires_at"])

        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)

    except (TypeError, ValueError):
        app.logger.error("Invalid expiry timestamp on download link.")
        return "This download link is unavailable.", 410

    if datetime.now(timezone.utc) >= expiry:
        return "This download link has expired.", 410

    # Read and decrypt before consuming the link.
    storage_path = get_safe_storage_path(record["storage_name"])

    if not storage_path.is_file():
        abort(404)

    try:
        encrypted_data = storage_path.read_bytes()
        decrypted_data = decrypt_file(encrypted_data)
    except (OSError, ValueError):
        app.logger.exception("Temporary file download failed.")
        abort(500)

    # Atomic database update: only one concurrent request can redeem it.
    if not mark_download_link_used(record["id"]):
        return "This download link has expired or has already been used.", 410

    response = send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=record["original_name"],
        mimetype="application/octet-stream",
        max_age=0,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.errorhandler(413)
def file_too_large(_error):
    return "Upload rejected: the maximum file size is 10 MiB.", 413


if __name__ == "__main__":
    app.run(debug=True)
