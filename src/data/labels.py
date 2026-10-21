from typing import Optional
import config


# Abstraction
def map_label(label: str) -> Optional[str]:
    """Map raw CICIDS2017 label to standard attack type."""
    text = str(label).strip()
    lower = text.lower()
    if text == "BENIGN" or lower == "benign":
        return "BENIGN"
    if "dos hulk" in lower or "dos goldeneye" in lower or "dos slowloris" in lower or "dos slowhttptest" in lower:
        return "DoS"
    if lower == "ddos":
        return "DDoS"
    if "portscan" in lower or "port scan" in lower:
        return "PortScan"
    if "patator" in lower:
        return "BruteForce"
    if "web attack" in lower:
        return "WebAttack"
    if lower == "bot":
        return "Bot"
    if any(d.lower() in lower for d in config.DROPPED_CLASSES):
        return None
    return None
