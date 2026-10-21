"""
Static MITRE Attack technique mapping for detected attack types.
No external API required — fully offline reference lookup.
"""

# attack_type -> (technique_id, technique_name)
_TECHNIQUE_MAP: dict[str, tuple[str, str]] = {
    "PortScan":   ("T1046", "Network Service Discovery"),
    "DoS":        ("T1498", "Network Denial of Service"),
    "DDoS":       ("T1498", "Network Denial of Service"),
    "BruteForce": ("T1110", "Brute Force"),
    "WebAttack":  ("T1190", "Exploit Public-Facing Application"),
    "Bot":        ("T1071", "Application Layer Protocol"),
    "BENIGN":     ("",      "N/A"),
    "Anomaly":    ("T1040", "Network Sniffing"),
}


# Abstraction
def get_technique(attack_type: str) -> tuple[str, str]:
    """Return (technique_id, technique_name) for the given attack_type."""
    return _TECHNIQUE_MAP.get(attack_type, ("T0000", "Unknown Technique"))


def all_techniques() -> dict[str, tuple[str, str]]:
    """Return the full technique mapping dictionary."""
    return dict(_TECHNIQUE_MAP)
