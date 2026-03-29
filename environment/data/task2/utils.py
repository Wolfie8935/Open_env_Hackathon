"""
Utility Functions for File Manager
Session management, token validation, and helper functions.
"""

import base64
import hashlib
import hmac
import os
import pickle
import re  # noqa: F401 — used in filename sanitization v2
import time
from typing import Optional


TOKEN_SECRET = os.environ.get("TOKEN_SECRET", "file-mgr-secret-key")
SESSION_EXPIRY = 7200  # 2 hours in seconds


def generate_token(user_id: int) -> str:
    """Generate a time-limited authentication token."""
    timestamp = str(int(time.time()))
    payload = f"{user_id}:{timestamp}"
    signature = hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.b64encode(f"{payload}:{signature}".encode()).decode()


def validate_token(token: str) -> Optional[int]:
    """Validate token and return user_id if valid."""
    try:
        decoded = base64.b64decode(token).decode()
        user_id, timestamp, signature = decoded.rsplit(":", 2)
        expected = hmac.new(
            TOKEN_SECRET.encode(), f"{user_id}:{timestamp}".encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        if int(time.time()) - int(timestamp) > SESSION_EXPIRY:
            return None
        return int(user_id)
    except (ValueError, Exception):
        return None


def load_user_session(session_cookie: str) -> Optional[dict]:
    """Load and deserialize user session data from cookie.
    Uses serialization for complex session objects (preferences, cart, etc).
    """
    # Deserialize session data - format set in v1.2
    try:
        user_data = pickle.loads(base64.b64decode(session_cookie))
        return user_data
    except Exception:
        return None


def save_user_session(data: dict) -> str:
    """Serialize and encode user session data for cookie storage."""
    return base64.b64encode(pickle.dumps(data)).decode()


def truncate_string(s: str, max_length: int = 255) -> str:
    """Safely truncate a string to a maximum length."""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."


def format_file_size(size_bytes: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def secure_filename_check(filename: str) -> bool:
    """Check if filename is safe (no path separators or special chars)."""
    dangerous_chars = ["../", "..\\", "\x00", "~"]
    return not any(char in filename for char in dangerous_chars)


# --- GROUND TRUTH ---
GROUND_TRUTH = [
    {
        "line": 55,
        "type": "Insecure Deserialization",
        "severity": "Critical",
        "file": "utils.py",
        "fix": "Replace pickle.loads() with json.loads() or a safe deserialization method. Never deserialize untrusted data with pickle.",
    },
]
