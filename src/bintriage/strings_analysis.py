"""Extract printable strings and pull out IOCs: IPs, URLs, domains, file paths."""

import re

# judgment call: domain matching is restricted to common + abuse-heavy TLDs,
# otherwise every "kernel32.dll" and "file.txt" in the binary matches as a domain
IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    
    "domain": re.compile(
        r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|ru|cn|xyz|top|info)\b",
        re.IGNORECASE,
    ),
    
    "windows_path": re.compile(r"[A-Za-z]:\\[^\s\"'<>|*?]+"),
}


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Runs of >= min_len printable ASCII chars found in the data."""
    
    #strings decided to keep
    found = []          
    #letters currently being collected
    run = []            

    for byte in data:
        
        #decides if the byte is printable or not, if T then printable, append.
        if 32 <= byte <= 126: 
           
            run.append(byte)    
            
        else:
            
            if len(run) >= min_len:          
    
                found.append(bytes(run).decode("ascii"))
            run = []                    
            

    if len(run) >= min_len:
        
        found.append(bytes(run).decode("ascii"))
        
    return found


def find_iocs(strings: list[str]) -> dict[str, list[str]]:
    """Match extracted strings against IOC patterns: ips, urls, domains, paths."""
    results = {}
    
    for category, pattern in IOC_PATTERNS.items():
        
        matches = set()                      
        
        for s in strings:
            
            matches.update(pattern.findall(s))
            
        results[category] = sorted(matches)  
        
    return results