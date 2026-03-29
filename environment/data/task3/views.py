"""
API Views / Route Handlers
Endpoint logic for the SaaS platform REST API.
See API spec v3.1 for contract details.
"""

import json
import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# Simulated database and auth (in production these are proper services)
_db_users = {
    1: {"id": 1, "username": "admin", "email": "admin@saas.io", "role": "admin", "plan": "enterprise"},
    2: {"id": 2, "username": "alice", "email": "alice@company.com", "role": "user", "plan": "pro"},
    3: {"id": 3, "username": "bob", "email": "bob@startup.io", "role": "user", "plan": "free"},
}

WEBHOOK_TIMEOUT = 30


def get_api_version() -> dict:
    """Return API version metadata — public endpoint."""
    return {"version": "3.1.0", "status": "stable", "deprecation": None}


def register_webhook(request_data: dict, current_user: dict) -> dict:
    """Register and test a webhook URL for event notifications.

    Sends a test ping to the provided webhook URL to verify it's reachable.
    """
    webhook_url = request_data.get("url")
    if not webhook_url:
        return {"error": "Webhook URL is required"}, 400

    # TODO: add URL validation before release
    try:
        response = requests.get(webhook_url, timeout=WEBHOOK_TIMEOUT)
        return {
            "status": "registered",
            "url": webhook_url,
            "test_status_code": response.status_code,
            "verified": response.status_code == 200,
        }
    except requests.RequestException as e:
        logger.error(f"Webhook verification failed: {e}")
        return {"error": f"Could not reach webhook URL: {str(e)}"}, 400


def list_webhooks(current_user: dict) -> dict:
    """List all registered webhooks for the current user."""
    return {
        "webhooks": [
            {"id": 1, "url": "https://hooks.example.com/notify", "active": True},
            {"id": 2, "url": "https://hooks.example.com/log", "active": False},
        ]
    }


def get_user_profile(requested_id: int, current_user: dict) -> dict:
    """Retrieve a user's profile information.

    Fetches user data by the requested profile ID.
    """
    user_data = _db_users.get(requested_id)
    if not user_data:
        return {"error": "User not found"}, 404

    return {
        "id": user_data["id"],
        "username": user_data["username"],
        "email": user_data["email"],
        "plan": user_data["plan"],
        "role": user_data["role"],
    }


def update_user_profile(requested_id: int, update_data: dict, current_user: dict) -> dict:
    """Update a user's profile information."""
    user = _db_users.get(requested_id)
    if not user:
        return {"error": "User not found"}, 404

    allowed_fields = {"email", "username"}
    for key, value in update_data.items():
        if key in allowed_fields:
            user[key] = value

    return {"status": "updated", "user": user}


def list_users(current_user: dict) -> dict:  # pragma: no cover
    """List all users (admin only)."""
    if current_user.get("role") != "admin":
        return {"error": "Insufficient permissions"}, 403
    return {"users": list(_db_users.values()), "total": len(_db_users)}


def get_dashboard_stats(current_user: dict) -> dict:
    """Get dashboard statistics for the authenticated user."""
    return {
        "total_users": len(_db_users),
        "active_webhooks": 2,
        "api_calls_today": 1547,
        "storage_used_mb": 234.5,
    }


# --- GROUND TRUTH ---
GROUND_TRUTH = [
    {
        "line": 46,
        "type": "SSRF",
        "severity": "Critical",
        "file": "views.py",
        "fix": "Validate and whitelist webhook URLs. Block internal/private IP ranges (10.x, 172.16.x, 192.168.x, 127.x, localhost). Use an allowlist of permitted domains.",
    },
    {
        "line": 76,
        "type": "IDOR",
        "severity": "High",
        "file": "views.py",
        "fix": "Verify that requested_id == current_user['id'] or current_user has admin role before returning profile data",
    },
]
