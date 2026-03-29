"""
Pydantic Models and Enums for the Security Vulnerability Scanner Environment.
All data structures used by the environment, graders, and API.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class VulnerabilityType(str, Enum):
    """All recognized vulnerability types across all tasks."""

    SQL_INJECTION = "SQL Injection"
    HARDCODED_SECRET = "Hardcoded Secret"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    BROKEN_AUTH = "Broken Authentication"
    WEAK_CRYPTO = "Weak Cryptography"
    SSRF = "SSRF"
    XXE = "XXE Injection"
    IDOR = "IDOR"
    MASS_ASSIGNMENT = "Mass Assignment"
    TIMING_ATTACK = "Timing Attack"
    CORS_MISCONFIGURATION = "CORS Misconfiguration"
    DEBUG_MODE = "Debug Mode"
    JWT_MISCONFIGURATION = "JWT Misconfiguration"

    @classmethod
    def normalize(cls, raw_string: str) -> Optional["VulnerabilityType"]:
        """Fuzzy-match a raw string to a VulnerabilityType value.

        Handles variations like 'sql injection', 'SQL_INJECTION', 'Sql Injection',
        plus common aliases and near-misses an LLM might produce.
        Returns None if no match found.
        """
        cleaned = raw_string.lower().replace("_", " ").replace("-", " ").strip()

        # Direct enum value match
        for member in cls:
            if member.value.lower() == cleaned:
                return member

        # Keyword-based fuzzy matching (order matters — more specific first)
        match_map = {
            # SQL Injection
            "sql injection": cls.SQL_INJECTION,
            "sql": cls.SQL_INJECTION,
            # Command Injection (before generic "injection")
            "command injection": cls.COMMAND_INJECTION,
            "code injection": cls.COMMAND_INJECTION,
            "eval injection": cls.COMMAND_INJECTION,
            "command": cls.COMMAND_INJECTION,
            "eval": cls.COMMAND_INJECTION,
            "exec": cls.COMMAND_INJECTION,
            # Path Traversal
            "path traversal": cls.PATH_TRAVERSAL,
            "directory traversal": cls.PATH_TRAVERSAL,
            "file traversal": cls.PATH_TRAVERSAL,
            "lfi": cls.PATH_TRAVERSAL,
            # Insecure Deserialization
            "insecure deserialization": cls.INSECURE_DESERIALIZATION,
            "unsafe deserialization": cls.INSECURE_DESERIALIZATION,
            "pickle deserialization": cls.INSECURE_DESERIALIZATION,
            "deserialization": cls.INSECURE_DESERIALIZATION,
            "pickle": cls.INSECURE_DESERIALIZATION,
            # JWT Misconfiguration (before "hardcoded" and "secret")
            "jwt misconfiguration": cls.JWT_MISCONFIGURATION,
            "jwt secret hardcoded": cls.JWT_MISCONFIGURATION,
            "hardcoded jwt": cls.JWT_MISCONFIGURATION,
            "jwt secret": cls.JWT_MISCONFIGURATION,
            "jwt weak": cls.JWT_MISCONFIGURATION,
            "jwt": cls.JWT_MISCONFIGURATION,
            "json web token": cls.JWT_MISCONFIGURATION,
            # Hardcoded Secret
            "hardcoded secret": cls.HARDCODED_SECRET,
            "hardcoded key": cls.HARDCODED_SECRET,
            "hardcoded password": cls.HARDCODED_SECRET,
            "hardcoded api key": cls.HARDCODED_SECRET,
            "hardcoded token": cls.HARDCODED_SECRET,
            "hard coded": cls.HARDCODED_SECRET,
            "hardcoded": cls.HARDCODED_SECRET,
            "secret": cls.HARDCODED_SECRET,
            # Timing Attack (before "weak crypto")
            "timing attack": cls.TIMING_ATTACK,
            "timing": cls.TIMING_ATTACK,
            "side channel": cls.TIMING_ATTACK,
            "insecure comparison": cls.TIMING_ATTACK,
            "timing side channel": cls.TIMING_ATTACK,
            # Broken Authentication
            "broken authentication": cls.BROKEN_AUTH,
            "broken auth": cls.BROKEN_AUTH,
            "missing authentication": cls.BROKEN_AUTH,
            "missing auth": cls.BROKEN_AUTH,
            "authentication bypass": cls.BROKEN_AUTH,
            "authentication": cls.BROKEN_AUTH,
            # Weak Cryptography
            "weak cryptography": cls.WEAK_CRYPTO,
            "weak crypto": cls.WEAK_CRYPTO,
            "weak hash": cls.WEAK_CRYPTO,
            "insecure hash": cls.WEAK_CRYPTO,
            "md5": cls.WEAK_CRYPTO,
            # SSRF
            "ssrf": cls.SSRF,
            "server side request": cls.SSRF,
            "server side request forgery": cls.SSRF,
            # XXE
            "xxe injection": cls.XXE,
            "xxe": cls.XXE,
            "xml external": cls.XXE,
            "xml entity": cls.XXE,
            "xml injection": cls.XXE,
            # IDOR
            "idor": cls.IDOR,
            "insecure direct": cls.IDOR,
            "insecure direct object": cls.IDOR,
            "direct object": cls.IDOR,
            # Mass Assignment
            "mass assignment": cls.MASS_ASSIGNMENT,
            "mass": cls.MASS_ASSIGNMENT,
            "attribute injection": cls.MASS_ASSIGNMENT,
            # CORS
            "cors misconfiguration": cls.CORS_MISCONFIGURATION,
            "cors": cls.CORS_MISCONFIGURATION,
            "cross origin": cls.CORS_MISCONFIGURATION,
            # Debug Mode
            "debug mode in production": cls.DEBUG_MODE,
            "debug mode": cls.DEBUG_MODE,
            "debug enabled": cls.DEBUG_MODE,
            "debug": cls.DEBUG_MODE,
        }

        for keyword, vuln_type in match_map.items():
            if keyword in cleaned:
                return vuln_type

        return None


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @classmethod
    def normalize(cls, raw_string: str) -> Optional["Severity"]:
        """Fuzzy-match severity string."""
        cleaned = raw_string.lower().strip()
        for member in cls:
            if member.value.lower() == cleaned:
                return member
        return None


class ActionType(str, Enum):
    """Available agent actions."""

    REPORT_VULNERABILITY = "report_vulnerability"
    REQUEST_FILE = "request_file"
    MARK_COMPLETE = "mark_complete"
    ADD_NOTE = "add_note"


class Finding(BaseModel):
    """A single vulnerability finding reported by the agent."""

    file: str = Field(description="The filename where the vulnerability was found")
    line_number: int = Field(ge=1, description="The line number of the vulnerability")
    vulnerability_type: str = Field(description="The type of vulnerability (must match a known type)")
    severity: str = Field(description="Severity level: Critical, High, Medium, or Low")
    description: str = Field(min_length=10, description="Detailed description of the vulnerability")
    suggested_fix: str = Field(min_length=10, description="Actionable fix recommendation")

    @field_validator("vulnerability_type")
    @classmethod
    def validate_vuln_type(cls, v: str) -> str:
        """Allow any string but warn if it doesn't match known types."""
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Allow any string for severity."""
        return v


class Observation(BaseModel):
    """What the agent sees after each step."""

    files: dict[str, str] = Field(description="Filename to full source code of currently visible files")
    current_findings: list[Finding] = Field(description="All vulnerabilities reported so far this episode")
    step_number: int = Field(description="Current step count")
    task_id: int = Field(description="Active task identifier (1, 2, or 3)")
    feedback: str = Field(description="Result of the last action taken")
    remaining_steps: int = Field(description="Steps remaining before episode auto-terminates")
    active_insights: list[str] = Field(default_factory=list, description="Insights unlocked by prior findings")
    suspicious_files: list[str] = Field(default_factory=list, description="Files flagged by discoveries")


class ReportVulnerabilityAction(BaseModel):
    """Payload for reporting a vulnerability."""

    file: str
    line_number: int = Field(ge=1)
    vulnerability_type: str
    severity: str
    description: str = Field(min_length=10)
    suggested_fix: str = Field(min_length=10)


class RequestFileAction(BaseModel):
    """Payload for requesting a hidden file."""

    filename: str


class MarkCompleteAction(BaseModel):
    """Payload for marking the episode complete."""

    pass


class AddNoteAction(BaseModel):
    """Payload for adding an analysis note."""

    note: str = Field(min_length=1)


class Action(BaseModel):
    """Agent action with type and payload."""

    action_type: ActionType
    payload: dict = Field(default_factory=dict)


class StepResult(BaseModel):
    """Result returned after each step."""

    observation: Observation
    reward: float = Field(ge=-0.5, le=0.6, description="Per-step reward clamped to [-0.5, 0.6]")
    done: bool
    info: dict = Field(default_factory=dict)


class TaskInfo(BaseModel):
    """Metadata about a task for the /tasks endpoint."""

    task_id: int
    name: str
    description: str
    difficulty: str
    max_steps: int
    num_vulnerabilities: int
    vulnerability_types: list[str]


class EpisodeState(BaseModel):
    """Full episode state for the /state endpoint."""

    task_id: int
    step_number: int
    max_steps: int
    findings: list[Finding]
    notes: list[str]
    visible_files: list[str]
    all_files: list[str]
    is_complete: bool
    cumulative_reward: float
