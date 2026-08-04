"""File type, size, and magic bytes."""
from pathlib import Path 
import magic

def identify_file(path: Path) -> dict:
    """Size, first bytes, and libmagic's opinion of what the file is."""
    size = path.stat().st_size
    
    
    with path.open("rb") as f:
        
        #grabbing a static 6 off the front
        
        first = f.read((6))
        
    
    return {
        
        #size metadata from OS stat, size of file
        "size" : size,
        
        #Scoring to match against
        "magic_hex": first.hex(),
        
        #libmagic cross check, gives description of what the file does essentially
        "description": magic.from_file(str(path)),
    }
