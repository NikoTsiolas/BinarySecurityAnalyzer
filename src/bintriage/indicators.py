"""Types shared by every module: one scored finding, and the final call."""

from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class Indicator:
    # short id like "packed_section"
    name: str    
    # which check it came from: entropy, imports, strings...     
    category: str     
    # how many points it adds to the risk score
    weight: int    
    # what was actually observed, e.g. ".text entropy = 7.64"   
    evidence: str  
    # why an analyst cares, in plain English   
    explanation: str  
