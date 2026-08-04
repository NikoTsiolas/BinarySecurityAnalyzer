"""Extract printable strings and pull out IOCs: IPs, URLs, domains, file paths."""


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