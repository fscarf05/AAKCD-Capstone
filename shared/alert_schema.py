from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Alert:
    agent: str
    severity: str
    activity: str
    kill_chain_stage: str
    mitre_technique: str
    confidence: float
    source_ip: Optional[str] = None

    def to_dict(self):
        return asdict(self)