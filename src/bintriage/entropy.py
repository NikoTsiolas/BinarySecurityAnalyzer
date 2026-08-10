"""Shannon entropy. Normal code sits around 6, compressed/encrypted data near 8.
    4.5 is standard for the human language in terms of randomness.
"""


import math
from collections import Counter

def shannon_entropy(data: bytes) -> float:
    """Bits per byte, 0.0 to 8.0. Empty input counts as 0.0."""
    if not data:
        return 0.0
    
    #maps bytes to frequency. 
    counts = Counter(data)
    
    #total bytes, stored once instead of calling every pass
    total = len(data)
    
    
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy
    