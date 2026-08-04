"""Types shared by every module: one scored finding, and the final call."""

from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class Indicator:
    name: str         # short id like "packed_section"
    category: str     # which check it came from: entropy, imports, strings...
    weight: int       # how many points it adds to the risk score
    evidence: str     # what was actually observed, e.g. ".text entropy = 7.64"
    explanation: str  # why an analyst cares, in plain English
