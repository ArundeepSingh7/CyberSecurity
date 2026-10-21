import os
from typing import Any, Optional
import requests

API_URL = os.environ.get("API_URL", "http://localhost:8000").rstrip("/")


class APIClient:
    """Client for communicating with the Cyber IDS FastAPI backend."""

    def __init__(self, base_url: str = API_URL) -> None:
        """Initialize client with base API URL."""
        self.base_url = base_url

    def get_health(self) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Query /health endpoint."""
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=5)
            if resp.status_code == 200:
                return resp.json(), None
            return None, f"HTTP {resp.status_code}: {resp.text}"
        except requests.RequestException as e:
            return None, f"Connection failed: {str(e)}"

    def get_strategies(self) -> tuple[Optional[list[str]], Optional[str]]:
        """Query /strategies endpoint."""
        try:
            resp = requests.get(f"{self.base_url}/strategies", timeout=5)
            if resp.status_code == 200:
                return resp.json(), None
            return None, f"HTTP {resp.status_code}: {resp.text}"
        except requests.RequestException as e:
            return None, f"Connection failed: {str(e)}"

    def analyze_csv(
        self,
        file_bytes: bytes,
        filename: str = "flows.csv",
        strategy: Optional[str] = None,
        threshold: Optional[float] = None,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Upload and analyze traffic flow CSV."""
        params: dict[str, Any] = {}
        if strategy:
            params["strategy"] = strategy
        if threshold is not None:
            params["threshold"] = threshold

        files = {"file": (filename, file_bytes, "text/csv")}
        try:
            resp = requests.post(
                f"{self.base_url}/analyze",
                files=files,
                params=params,
                timeout=60,
            )
            if resp.status_code == 200:
                return resp.json(), None
            detail = resp.json().get("detail", resp.text) if resp.headers.get("content-type") == "application/json" else resp.text
            return None, f"HTTP {resp.status_code}: {detail}"
        except requests.RequestException as e:
            return None, f"Analysis request failed: {str(e)}"

    def get_alerts(self, limit: int = 100) -> tuple[Optional[list[dict[str, Any]]], Optional[str]]:
        """Fetch recorded alerts."""
        try:
            resp = requests.get(
                f"{self.base_url}/alerts",
                params={"limit": limit},
                timeout=5,
            )
            if resp.status_code == 200:
                return resp.json(), None
            return None, f"HTTP {resp.status_code}: {resp.text}"
        except requests.RequestException as e:
            return None, f"Alerts request failed: {str(e)}"

    def get_metrics(self) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Fetch model evaluation metrics."""
        try:
            resp = requests.get(f"{self.base_url}/metrics", timeout=5)
            if resp.status_code == 200:
                return resp.json(), None
            detail = resp.json().get("detail", resp.text) if resp.headers.get("content-type") == "application/json" else resp.text
            return None, f"HTTP {resp.status_code}: {detail}"
        except requests.RequestException as e:
            return None, f"Metrics request failed: {str(e)}"

    def update_config(
        self,
        strategy: Optional[str] = None,
        threshold: Optional[float] = None,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Update backend detection configuration."""
        payload: dict[str, Any] = {}
        if strategy is not None:
            payload["strategy"] = strategy
        if threshold is not None:
            payload["threshold"] = threshold
        try:
            resp = requests.post(f"{self.base_url}/config", json=payload, timeout=5)
            if resp.status_code == 200:
                return resp.json(), None
            return None, f"HTTP {resp.status_code}: {resp.text}"
        except requests.RequestException as e:
            return None, f"Config update failed: {str(e)}"

    # ---- Live capture ----

    def live_start(
        self,
        window_seconds: float = 2.0,
        strategy: Optional[str] = None,
        threshold: Optional[float] = None,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Start live capture."""
        payload: dict[str, Any] = {"window_seconds": window_seconds}
        if strategy:
            payload["strategy"] = strategy
        if threshold is not None:
            payload["threshold"] = threshold
        try:
            resp = requests.post(f"{self.base_url}/live/start", json=payload, timeout=5)
            return (resp.json(), None) if resp.status_code == 200 else (None, resp.text)
        except requests.RequestException as e:
            return None, str(e)

    def live_stop(self) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Stop live capture."""
        try:
            resp = requests.post(f"{self.base_url}/live/stop", timeout=5)
            return (resp.json(), None) if resp.status_code == 200 else (None, resp.text)
        except requests.RequestException as e:
            return None, str(e)

    def live_status(self) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Get live capture status."""
        try:
            resp = requests.get(f"{self.base_url}/live/status", timeout=5)
            return (resp.json(), None) if resp.status_code == 200 else (None, resp.text)
        except requests.RequestException as e:
            return None, str(e)

    def live_alerts(self, since_id: int = 0) -> tuple[Optional[list[dict[str, Any]]], Optional[str]]:
        """Fetch live alerts since a given id."""
        try:
            resp = requests.get(
                f"{self.base_url}/live/alerts",
                params={"since_id": since_id},
                timeout=5,
            )
            return (resp.json(), None) if resp.status_code == 200 else (None, resp.text)
        except requests.RequestException as e:
            return None, str(e)

    def live_ingest(self, payload: dict[str, Any]) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Ingest a direct flow event (for telemetry fallback mode)."""
        try:
            resp = requests.post(f"{self.base_url}/live/ingest", json=payload, timeout=5)
            return (resp.json(), None) if resp.status_code == 200 else (None, resp.text)
        except requests.RequestException as e:
            return None, str(e)

    # ---- Threat intelligence ----

    def intel_summary(self) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Fetch threat intelligence summary."""
        try:
            resp = requests.get(f"{self.base_url}/intel/summary", timeout=5)
            return (resp.json(), None) if resp.status_code == 200 else (None, resp.text)
        except requests.RequestException as e:
            return None, str(e)

    def intel_ip(self, ip: str) -> tuple[Optional[list[dict[str, Any]]], Optional[str]]:
        """Fetch alert history for an IP."""
        try:
            resp = requests.get(f"{self.base_url}/intel/ip/{ip}", timeout=5)
            return (resp.json(), None) if resp.status_code == 200 else (None, resp.text)
        except requests.RequestException as e:
            return None, str(e)
