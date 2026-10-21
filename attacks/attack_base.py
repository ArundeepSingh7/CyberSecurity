"""
For educational use against your own local test environment only.

Abstract base class for all simulated attacks.
Mirrors BaseDetector's abstraction style for project consistency.
"""
from abc import ABC, abstractmethod
import sys


# Abstraction
class BaseAttack(ABC):
    """Abstract base for all traffic-pattern attack simulations."""

    def __init__(self, target: str = "127.0.0.1", port: int = 5000, duration: int = 10) -> None:
        """Initialise with target, port, and duration."""
        self.target = target
        self.port = port
        self.duration = duration
        self._check_target()

    def _check_target(self) -> None:
        """Safety guard: refuse to run against any non-localhost target."""
        allowed = {"127.0.0.1", "localhost", "::1"}
        if self.target not in allowed:
            print(
                f"[SAFETY] Target '{self.target}' is NOT localhost. "
                "This tool is for educational use against your own "
                "local test environment ONLY. Exiting."
            )
            sys.exit(1)

    # Abstraction
    @abstractmethod
    def run(self) -> None:
        """Execute the simulated attack pattern."""

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(target={self.target}, port={self.port}, duration={self.duration}s)"
