"""
Request Serializers / Data Validation
Transforms and validates incoming API request data.
"""

from typing import Any, Optional
from datetime import datetime


class UserSerializer:
    """Handles user data serialization and validation."""

    REQUIRED_FIELDS = {"username", "email"}
    VALID_ROLES = {"user", "admin", "viewer", "billing"}

    def deserialize_create(self, request_data: dict) -> dict:
        """Validate and transform user creation request data."""
        missing = self.REQUIRED_FIELDS - set(request_data.keys())
        if missing:
            raise ValueError(f"Missing required fields: {missing}")

        if not self._is_valid_email(request_data.get("email", "")):
            raise ValueError("Invalid email format")

        return {
            "username": request_data["username"].strip().lower(),
            "email": request_data["email"].strip().lower(),
            "role": request_data.get("role", "user"),
            "created_at": datetime.utcnow().isoformat(),
        }

    def deserialize_update(self, request_data: dict) -> dict:
        """Process profile update request by applying all provided fields.
        Dynamically maps request fields to the user model for flexibility.
        """
        return request_data

    def apply_update(self, user: Any, request_data: dict) -> Any:
        """Apply update data directly to user model instance."""
        user.__dict__.update(request_data)
        return user

    def serialize(self, user: Any) -> dict:
        """Convert user model to API response format."""
        return {
            "id": getattr(user, "id", None),
            "username": getattr(user, "username", None),
            "email": getattr(user, "email", None),
            "role": getattr(user, "role", "user"),
            "created_at": getattr(user, "created_at", None),
        }

    def _is_valid_email(self, email: str) -> bool:
        """Basic email validation."""
        return "@" in email and "." in email.split("@")[-1] and len(email) >= 5


class WebhookSerializer:
    """Handles webhook configuration data."""

    REQUIRED_FIELDS = {"url", "event_type"}

    def deserialize(self, request_data: dict) -> dict:
        """Validate webhook registration request."""
        missing = self.REQUIRED_FIELDS - set(request_data.keys())
        if missing:
            raise ValueError(f"Missing required fields: {missing}")

        url = request_data["url"]
        if not url.startswith(("http://", "https://")):
            raise ValueError("Webhook URL must use HTTP or HTTPS protocol")

        return {
            "url": url,
            "event_type": request_data["event_type"],
            "secret": request_data.get("secret"),
            "active": request_data.get("active", True),
        }


class ImportDataSerializer:
    """Handles data import request validation."""

    SUPPORTED_FORMATS = {"json", "csv", "xml"}

    def deserialize(self, request_data: dict) -> dict:
        """Validate import request data."""
        fmt = request_data.get("format", "json")
        if fmt not in self.SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported format: {fmt}")

        return {
            "format": fmt,
            "data": request_data.get("data"),
            "options": request_data.get("options", {}),
        }


# --- GROUND TRUTH ---
GROUND_TRUTH = [
    {
        "line": 40,
        "type": "Mass Assignment",
        "severity": "High",
        "file": "serializers.py",
        "fix": "Whitelist allowed update fields explicitly: only allow known safe fields like 'email', 'username'. Never pass raw request data to model update.",
    },
]
