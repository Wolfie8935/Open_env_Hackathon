"""
HTTP client for this environment's REST API (same contract as `inference.py`).

OpenEnv CLI `openenv push` requires a root `client.py`; the hackathon agent uses
`httpx` in `inference.py` — this module is a small `requests`-based helper for
tools that expect a dedicated client class.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import requests


class SecurityScannerEnvClient:
    """Thin client for POST /reset, POST /step, GET /state."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 120.0,
        default_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = float(timeout)
        self._http = requests.Session()
        if default_headers:
            self._http.headers.update(default_headers)

    def reset(self, task_id: int = 1) -> Dict[str, Any]:
        r = self._http.post(
            f"{self._base}/reset",
            json={"task_id": int(task_id)},
            timeout=self._timeout,
        )
        r.raise_for_status()
        return r.json()

    def step(self, action: Dict[str, Any]) -> Dict[str, Any]:
        r = self._http.post(
            f"{self._base}/step",
            json=action,
            timeout=self._timeout,
        )
        r.raise_for_status()
        return r.json()

    def state(self) -> Dict[str, Any]:
        r = self._http.get(f"{self._base}/state", timeout=self._timeout)
        r.raise_for_status()
        return r.json()

    def close(self) -> None:
        self._http.close()
