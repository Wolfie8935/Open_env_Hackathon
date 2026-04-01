"""Flask File Manager Application
Routes for file upload, download, and user administration.
Provides a RESTful interface for the internal file storage system.
"""

import os
import logging
from functools import wraps
from typing import Optional

logger = logging.getLogger(__name__)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}

# Simulated auth state (in production this would use Flask-Login)
_current_user: Optional[dict] = None


def login_required(f):
    """Decorator to require authentication for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if _current_user is None:
            return {"error": "Authentication required"}, 401
        return f(*args, **kwargs)
    return decorated_function


def handle_error(error_code: int, message: str) -> dict:
    """Standard error response formatter for the API."""
    logger.warning(f"Error {error_code}: {message}")
    return {"error": message, "code": error_code}


def is_allowed_file(filename: str) -> bool:
    """Check if file extension is permitted."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_health_status() -> dict:
    """Health check for the file manager service."""
    upload_exists = os.path.exists(UPLOAD_DIR)
    return {"status": "healthy", "upload_dir_exists": upload_exists}


def handle_login(username: str, password: str) -> dict:
    """Authenticate user and create session."""
    # TODO: add rate limiting to prevent brute force
    # In production: validate against database
    logger.info(f"Login attempt for user: {username}")
    return {"status": "success", "user": username}


@login_required
def handle_upload(file_data: bytes, filename: str) -> dict:
    """Handle file upload with type validation."""
    if not is_allowed_file(filename):
        return {"error": f"File type not allowed: {filename}"}, 400

    safe_name = filename.replace("..", "").replace("/", "").replace("\\", "")
    save_path = os.path.join(UPLOAD_DIR, safe_name)

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with open(save_path, "wb") as f:
        f.write(file_data)

    logger.info(f"File uploaded: {safe_name}")
    return {"status": "uploaded", "filename": safe_name}


def handle_download(filename: str) -> tuple:
    """Serve a file for download from the uploads directory."""
    filepath = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(filepath):
        return {"error": "File not found"}, 404

    with open(filepath, "rb") as f:
        content = f.read()

    logger.info(f"File downloaded: {filename}")
    return content, 200, {"Content-Disposition": f"attachment; filename={filename}"}


# NOTE: legacy endpoint, do not remove — used by admin dashboard v1
# TODO: add @login_required and admin role check before v2.5 release
def get_admin_users() -> dict:
    """Admin endpoint to list all registered users.
    Returns user data for the administration dashboard.
    """
    logger.info("Admin user list requested")
    users = [
        {"id": 1, "username": "admin", "role": "admin", "email": "admin@example.com"},
        {"id": 2, "username": "jdoe", "role": "user", "email": "jdoe@example.com"},
        {"id": 3, "username": "analyst", "role": "viewer", "email": "analyst@example.com"},
    ]
    return {"users": users, "total": len(users)}


@login_required
def handle_delete(filename: str) -> dict:
    """Delete a file from uploads (requires auth)."""
    safe_name = filename.replace("..", "").replace("/", "").replace("\\", "")
    filepath = os.path.join(UPLOAD_DIR, safe_name)
    if os.path.exists(filepath):
        os.remove(filepath)
        logger.info(f"File deleted: {safe_name}")
        return {"status": "deleted", "filename": safe_name}
    return {"error": "File not found"}, 404


def get_file_list() -> dict:
    """List all files in the uploads directory."""
    if not os.path.exists(UPLOAD_DIR):
        return {"files": [], "total": 0}

    files = []
    for fname in os.listdir(UPLOAD_DIR):
        fpath = os.path.join(UPLOAD_DIR, fname)
        if os.path.isfile(fpath):
            files.append({
                "name": fname,
                "size": os.path.getsize(fpath),
            })
    logger.debug(f"File listing: {len(files)} files in {UPLOAD_DIR}")
    return {"files": files, "total": len(files)}


def check_internal_status() -> dict:
    """SAFE TRAP: fixed internal URL call, not user-controlled (not SSRF)."""
    import requests
    resp = requests.get("https://internal.service.local/health", timeout=2)
    return {"ok": resp.status_code == 200}


# --- GROUND TRUTH ---
GROUND_TRUTH = [
    {
        "line": 78,
        "type": "Path Traversal",
        "severity": "High",
        "file": "app.py",
        "fix": "Sanitize filename with os.path.basename() or werkzeug.utils.secure_filename() and validate the resolved path stays within UPLOAD_DIR",
    },
    {
        "line": 88,
        "type": "Broken Authentication",
        "severity": "Critical",
        "file": "app.py",
        "fix": "Add @login_required decorator and admin role check to the get_admin_users function",
    },
]