# client.py
import httpx
from environment.models import Action, Observation, StepResult, TaskInfo

class SecurityScannerClient:
    """
    HTTP client for the Security Vulnerability Scanner environment.
    Install: pip install git+https://huggingface.co/spaces/USERNAME/security-scanner
    Usage:
        client = SecurityScannerClient("https://your-space.hf.space")
        obs = client.reset(task_id=1)
        result = client.step(action)
    """
    
    def __init__(self, base_url: str = "http://localhost:7860", timeout: int = 60):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)
    
    def reset(self, task_id: int = 1) -> Observation:
        resp = self._client.post(
            f"{self.base_url}/reset",
            json={"task_id": task_id}
        )
        resp.raise_for_status()
        return Observation(**resp.json())
    
    def step(self, action: Action) -> StepResult:
        resp = self._client.post(
            f"{self.base_url}/step",
            json=action.model_dump()
        )
        resp.raise_for_status()
        return StepResult(**resp.json())
    
    def state(self) -> dict:
        resp = self._client.get(f"{self.base_url}/state")
        resp.raise_for_status()
        return resp.json()
    
    def tasks(self) -> list[TaskInfo]:
        resp = self._client.get(f"{self.base_url}/tasks")
        resp.raise_for_status()
        return [TaskInfo(**t) for t in resp.json()]
    
    def health(self) -> dict:
        resp = self._client.get(f"{self.base_url}/health")
        resp.raise_for_status()
        return resp.json()
    
    def close(self):
        self._client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()