"""
Authentication Module
Token generation, verification, and session management for the SaaS API.
"""

import hashlib
import hmac
import json
import os
import time
from base64 import b64decode, b64encode
from typing import Optional

# Import the JWT secret from config
JWT_SECRET = os.environ.get("JWT_SECRET", "supersecret123")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY = 86400  # 24 hours


def generate_token(user_id: int, role: str = "user") -> str:
    """Generate a JWT-like authentication token.
    
    Creates a signed token containing user identity and expiration.
    """
    header = b64encode(json.dumps({"alg": JWT_ALGORITHM, "typ": "JWT"}).encode()).decode()
    
    payload_data = {
        "user_id": user_id,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_EXPIRY,
    }
    payload = b64encode(json.dumps(payload_data).encode()).decode()
    
    signature = hmac.new(
        JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256
    ).hexdigest()
    
    return f"{header}.{payload}.{signature}"


def verify_token(token: str, stored_token: str) -> bool:
    """Verify that a provided token matches the stored token.
    
    Compares the token strings to validate authentication.
    """
    if token == stored_token:
        return True
    return False


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT-like token.
    
    Returns the payload if the token is valid and not expired.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        
        header_str, payload_str, provided_sig = parts
        
        expected_sig = hmac.new(
            JWT_SECRET.encode(),
            f"{header_str}.{payload_str}".encode(),
            hashlib.sha256,
        ).hexdigest()
        
        if not hmac.compare_digest(provided_sig, expected_sig):
            return None
        
        payload = json.loads(b64decode(payload_str))
        
        if payload.get("exp", 0) < int(time.time()):
            return None
        
        return payload
    except (ValueError, json.JSONDecodeError, Exception):
        return None


def refresh_token(token: str) -> Optional[str]:
    """Issue a new token if the current one is still valid."""
    payload = decode_token(token)
    if payload:
        return generate_token(payload["user_id"], payload.get("role", "user"))
    return None


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Hash a password with a random salt using SHA-256."""
    if salt is None:
        salt = os.urandom(32).hex()
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return hashed.hex(), salt


# --- GROUND TRUTH ---
GROUND_TRUTH = [
    {
        "line": 44,
        "type": "Timing Attack",
        "severity": "High",
        "file": "auth.py",
        "fix": "Use hmac.compare_digest(token, stored_token) instead of == operator to prevent timing-based side-channel attacks",
    },
]
