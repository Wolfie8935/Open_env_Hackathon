"""
Database Models for File Manager Application
User and File models with authentication support.
Part of the v2 schema — see migration doc DM-042.
"""

import hashlib
from datetime import datetime
from typing import Optional


class User:
    """User model with authentication and role management."""

    VALID_ROLES = {"admin", "user", "viewer"}

    def __init__(self, user_id: int, username: str, email: str, role: str = "user"):
        self.id = user_id
        self.username = username
        self.email = email
        self.password_hash = None
        self.role = role
        self.created_at = datetime.utcnow()
        self.last_login = None
        self.is_active = True

    def set_password(self, password: str) -> None:
        """Hash and store the user's password."""
        self.password_hash = hashlib.md5(password.encode()).hexdigest()

    def check_password(self, password: str) -> bool:
        """Verify a password against the stored hash."""
        return self.password_hash == hashlib.md5(password.encode()).hexdigest()

    def update_login(self) -> None:
        """Record a successful login timestamp."""
        self.last_login = datetime.utcnow()

    def has_role(self, required_role: str) -> bool:
        """Check if user has the specified role."""
        return self.role == required_role

    def to_dict(self) -> dict:
        """Serialize user to dictionary (excludes password hash)."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "is_active": self.is_active,
        }


class FileRecord:
    """Represents an uploaded file in the system."""

    def __init__(self, file_id: int, filename: str, owner_id: int, size_bytes: int):
        self.id = file_id
        self.filename = filename
        self.owner_id = owner_id
        self.size_bytes = size_bytes
        self.uploaded_at = datetime.utcnow()
        self.mime_type: Optional[str] = None
        self.checksum: Optional[str] = None

    def compute_checksum(self, content: bytes) -> str:
        """Compute SHA-256 checksum of file content."""
        self.checksum = hashlib.sha256(content).hexdigest()
        return self.checksum


# --- GROUND TRUTH ---
GROUND_TRUTH = [
    {
        "line": 30,
        "type": "Weak Cryptography",
        "severity": "High",
        "file": "models.py",
        "fix": "Replace MD5 with bcrypt or argon2 for password hashing: import bcrypt; self.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
    },
]
