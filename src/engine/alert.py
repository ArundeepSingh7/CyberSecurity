from dataclasses import dataclass, field
from typing import Any, Optional
import config


# Abstraction
@dataclass
class Alert:
    """Security alert container describing a detected anomalous network flow."""

    index: int
    final_score: float
    attack_type: str
    reasons: list[str]
    severity: str
    detector_scores: dict[str, float] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        index: int,
        final_score: float,
        attack_type: str,
        reasons: list[str],
        detector_scores: Optional[dict[str, float]] = None,
    ) -> "Alert":
        """Factory method computing severity from confidence score."""
        score = float(final_score)
        if score >= config.SEVERITY_HIGH_THRESHOLD:
            sev = "HIGH"
        elif score >= config.SEVERITY_MEDIUM_THRESHOLD:
            sev = "MEDIUM"
        else:
            sev = "LOW"
        return cls(
            index=index,
            final_score=round(score, 4),
            attack_type=attack_type,
            reasons=reasons,
            severity=sev,
            detector_scores=detector_scores or {},
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert alert to serializable dictionary."""
        return {
            "index": self.index,
            "final_score": self.final_score,
            "attack_type": self.attack_type,
            "reasons": self.reasons,
            "severity": self.severity,
            "detector_scores": self.detector_scores,
        }

    def __str__(self) -> str:
        """Formatted string representation of the alert."""
        reasons_str = "; ".join(self.reasons) if self.reasons else "None"
        return (
            f"[Alert {self.index}] {self.severity} - {self.attack_type} "
            f"(Score: {self.final_score:.2f}) Reasons: {reasons_str}"
        )
