"""
Application Configuration
Settings for the SaaS platform API service.
Loads from environment with sensible defaults for local development.
"""

import os
DEBUG = True  # TODO: disable before deploy
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost:5432/saas_app")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

JWT_SECRET = "supersecret123"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24

ALLOWED_HOSTS = ["api.example.com", "localhost"]
LOG_LEVEL = "DEBUG" if DEBUG else "INFO"
RATE_LIMIT_PER_MINUTE = 60

# External service configuration
WEBHOOK_TIMEOUT = 30
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50MB
SUPPORTED_IMPORT_FORMATS = ["json", "csv", "xml"]

# Feature flags
ENABLE_XML_IMPORT = True
ENABLE_WEBHOOKS = True
ENABLE_ADMIN_API = True

# Monitoring — set via deploy config
SENTRY_DSN = os.environ.get("SENTRY_DSN", "")
METRICS_ENABLED = os.environ.get("METRICS_ENABLED", "false").lower() == "true"


def get_database_url() -> str:
    """Return the active database URL based on environment."""
    if DEBUG:
        return DATABASE_URL
    return os.environ["DATABASE_URL"]


def get_cors_config() -> dict:
    """Return CORS configuration for the API."""
    return {
        "allow_origins": ALLOWED_HOSTS,
        "allow_methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Authorization", "Content-Type"],
    }


# --- GROUND TRUTH ---
GROUND_TRUTH = [
    {
        "line": 8,
        "type": "Debug Mode",
        "severity": "Medium",
        "file": "config.py",
        "fix": "Set DEBUG = False in production or use DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'",
    },
    {
        "line": 12,
        "type": "JWT Misconfiguration",
        "severity": "Critical",
        "file": "config.py",
        "fix": "Use a strong, randomly generated secret from environment: JWT_SECRET = os.environ['JWT_SECRET'] with a cryptographically random value",
    },
]
