"""
Request Middleware
Preprocessing, logging, and content parsing for incoming API requests.
Handles content negotiation and request lifecycle management.
"""

import json
import logging
import time
import xml.etree.ElementTree as ET
from io import BytesIO
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class RequestLogger:
    """Middleware that logs request details for monitoring."""

    def __init__(self):
        self.request_count = 0

    def log_request(self, method: str, path: str, body_size: int) -> dict:
        """Log incoming request metadata."""
        self.request_count += 1
        log_entry = {
            "request_id": self.request_count,
            "method": method,
            "path": path,
            "body_size": body_size,
            "timestamp": time.time(),
        }
        logger.info(f"Request #{self.request_count}: {method} {path}")
        return log_entry

    def get_stats(self) -> dict:
        """Return request statistics for monitoring dashboard."""
        return {"total_requests": self.request_count}


class ContentTypeHandler:
    """Detects and parses request body based on content type."""

    SUPPORTED_TYPES = {
        "application/json": "json",
        "application/xml": "xml",
        "text/xml": "xml",
        "text/csv": "csv",
        "multipart/form-data": "form",
    }

    def detect_content_type(self, content_type: str) -> str:
        """Map content-type header to internal format identifier."""
        for ct, fmt in self.SUPPORTED_TYPES.items():
            if ct in content_type.lower():
                return fmt
        return "unknown"

    def parse_body(self, body: bytes, content_type: str) -> Any:
        """Route body parsing to the appropriate handler."""
        fmt = self.detect_content_type(content_type)
        if fmt == "json":
            return self._parse_json(body)
        elif fmt == "xml":
            return self._parse_xml(body)
        elif fmt == "csv":
            return self._parse_csv(body)
        else:
            return {"raw": body.decode("utf-8", errors="replace")}

    def _parse_json(self, body: bytes) -> Any:
        """Parse JSON request body."""
        try:
            return json.loads(body)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            raise ValueError(f"Invalid JSON: {e}")

    def _parse_xml(self, body: bytes) -> dict:
        """Parse XML request body for data import feature.
        Converts XML elements to a nested dictionary structure.
        """
        try:
            tree = ET.parse(BytesIO(body))
            root = tree.getroot()
            return self._xml_to_dict(root)
        except ET.ParseError as e:
            logger.error(f"XML parse error: {e}")
            raise ValueError(f"Invalid XML: {e}")

    def _xml_to_dict(self, element: ET.Element) -> dict:
        """Recursively convert XML element tree to dictionary."""
        result = {}
        for child in element:
            if len(child) > 0:
                result[child.tag] = self._xml_to_dict(child)
            else:
                result[child.tag] = child.text
        if element.attrib:
            result["@attributes"] = dict(element.attrib)
        return result

    def _parse_csv(self, body: bytes) -> list[list[str]]:
        """Parse CSV request body into rows."""
        text = body.decode("utf-8")
        rows = []
        for line in text.strip().split("\n"):
            rows.append([cell.strip() for cell in line.split(",")])
        return rows


class RateLimiter:
    """Simple in-memory rate limiter."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = {}

    def is_allowed(self, client_id: str) -> bool:
        """Check if a client is within their rate limit."""
        now = time.time()
        if client_id not in self._requests:
            self._requests[client_id] = []

        # Clean old entries
        self._requests[client_id] = [
            t for t in self._requests[client_id]
            if now - t < self.window_seconds
        ]

        if len(self._requests[client_id]) >= self.max_requests:
            return False

        self._requests[client_id].append(now)
        return True

    def reset(self, client_id: str) -> None:  # pragma: no cover
        """Reset rate limit for a specific client."""
        self._requests.pop(client_id, None)


# --- GROUND TRUTH ---
GROUND_TRUTH = [
    {
        "line": 85,
        "type": "XXE Injection",
        "severity": "Critical",
        "file": "middleware.py",
        "fix": "Use defusedxml.ElementTree instead of xml.etree.ElementTree, or disable external entity processing to prevent XXE attacks",
    },
]
