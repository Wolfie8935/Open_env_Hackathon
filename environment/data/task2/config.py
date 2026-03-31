"""
Flask Application Configuration
Centralized settings for the file management application.
Follows 12-factor app principles where possible.
"""

import os
from datetime import timedelta


SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change-me-in-production")
DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///filemanager.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
CORS_ORIGINS = "*"
CORS_SUPPORTS_CREDENTIALS = True
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "doc", "docx"}
SESSION_LIFETIME = timedelta(hours=2)
RATE_LIMIT = "100/hour"

# TODO: restrict origins before deploy — wildcard is dev-only
def init_cors(app):
    """Initialize CORS settings for the application."""
    from flask_cors import CORS
    CORS(app, origins=CORS_ORIGINS, supports_credentials=CORS_SUPPORTS_CREDENTIALS)


def is_allowed_file(filename: str) -> bool:
    """Check if a file extension is in the whitelist."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_max_upload_mb() -> float:
    """Return max upload size in megabytes for display purposes."""
    return MAX_CONTENT_LENGTH / (1024 * 1024)


# --- GROUND TRUTH ---
GROUND_TRUTH = [
    {
        "line": 14,
        "type": "CORS Misconfiguration",
        "severity": "Medium",
        "file": "config.py",
        "fix": "Restrict CORS_ORIGINS to specific trusted domains instead of wildcard '*', especially when credentials are supported",
    },
]
