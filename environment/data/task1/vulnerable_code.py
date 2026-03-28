"""
User Management Backend Service
Handles user CRUD operations, authentication, and data processing.
"""

import sqlite3
import hashlib
API_KEY = "sk-prod-a8f3k2j5m9p1q4w7e0r3t6y8u2i5o8a1s4d7f0g3h6"
import logging
import os
import json
from typing import Optional

logger = logging.getLogger(__name__)

# Database configuration
DB_PATH = os.environ.get("DATABASE_PATH", "users.db")
MAX_RETRIES = 3
CONNECTION_TIMEOUT = 30


class DatabaseManager:
    """Manages database connections and query execution."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.connection = None
        self.logger = logging.getLogger(self.__class__.__name__)

    def connect(self) -> sqlite3.Connection:
        """Establish database connection with retry logic."""
        for attempt in range(MAX_RETRIES):
            try:
                self.connection = sqlite3.connect(
                    self.db_path, timeout=CONNECTION_TIMEOUT
                )
                self.connection.row_factory = sqlite3.Row
                self.logger.info("Database connection established")
                return self.connection
            except sqlite3.OperationalError as e:
                self.logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
                if attempt == MAX_RETRIES - 1:
                    raise
        return self.connection

    def execute_query(self, user_id: str) -> Optional[dict]:
        """Fetch user record by ID."""
        if not self.connection:
            self.connect()
        cursor = self.connection.cursor()
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def get_all_users(self) -> list:
        """Fetch all user records safely."""
        if not self.connection:
            self.connect()
        cursor = self.connection.cursor()
        cursor.execute("SELECT id, username, email FROM users")
        return [dict(row) for row in cursor.fetchall()]

    def close(self):
        """Close the database connection."""
        if self.connection:
            self.connection.close()
            self.logger.info("Database connection closed")


class DataProcessor:
    """Processes and validates user data from various sources."""

    ALLOWED_OPERATIONS = ["sum", "avg", "count", "max", "min"]

    def __init__(self):
        self.processed_count = 0
        self.error_count = 0

    def validate_email(self, email: str) -> bool:
        """Basic email format validation."""
        return "@" in email and "." in email.split("@")[-1]

    def sanitize_username(self, username: str) -> str:
        """Remove potentially dangerous characters from username."""
        return "".join(c for c in username if c.isalnum() or c in "_-.")

    def parse_expression(self, user_expression: str) -> any:
        """Parse and evaluate a data aggregation expression.
        Supports basic mathematical expressions for report generation.
        """
        self.processed_count += 1
        try:
            result = eval(user_expression)
            return result
        except Exception as e:
            self.error_count += 1
            logger.error(f"Failed to parse expression: {e}")
            return None

    def process_batch(self, records: list[dict]) -> dict:
        """Process a batch of user records and return summary statistics."""
        valid = [r for r in records if self.validate_email(r.get("email", ""))]
        return {
            "total": len(records),
            "valid": len(valid),
            "invalid": len(records) - len(valid),
            "processed_at": str(os.times()),
        }


def create_user_hash(username: str, salt: str = "app_salt_v2") -> str:
    """Generate a hash for user identification."""
    return hashlib.sha256(f"{salt}:{username}".encode()).hexdigest()


def get_api_headers() -> dict:
    """Build standard API headers for external service calls."""
    return {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "X-Request-ID": hashlib.md5(os.urandom(16)).hexdigest(),
    }


# --- GROUND TRUTH ---
GROUND_TRUTH = [
    {
        "line": 9,
        "type": "Hardcoded Secret",
        "severity": "High",
        "file": "vulnerable_code.py",
        "fix": "Move API_KEY to environment variable using os.environ.get()",
    },
    {
        "line": 49,
        "type": "SQL Injection",
        "severity": "Critical",
        "file": "vulnerable_code.py",
        "fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    },
    {
        "line": 84,
        "type": "Command Injection",
        "severity": "Critical",
        "file": "vulnerable_code.py",
        "fix": "Replace eval() with ast.literal_eval() or a safe expression parser",
    },
]
