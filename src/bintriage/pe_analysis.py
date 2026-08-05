"""PE aka portable executable, structure via pefile: timestamp, sections, imports."""

from datetime import datetime, timezone
from pathlib import Path


import pefile

from bintriage.entropy import shannon_entropy 

def analyze_pe(path: Path) -> dict | None:
    """Timestamp, sections (with entropy), imports. None if not a PE at all.

    Raises pefile.PEFormatError on a malformed PE - caller records that as a fact.
    """
    
    #cheap gate: no MZ sig, not a PE, not our problem
    
    with path.open("rb") as f:
        
        if f.read(2) != b"MZ":
        
            return None
    
    pe = pefile.PE(str(path))
    
    sections = []
    
    for sec in pe.sections:
        sections.append({
            "name": sec.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
            
            "raw_size": sec.SizeOfRawData,
            
            "virtual_size": sec.Misc_VirtualSize,
            #the sections raw bytes off disk
            "entropy": round(shannon_entropy(sec.get_data()), 2),  
            
            #executable Bit    
            "executable": bool(sec.Characteristics & 0x20000000),
            
            #writable Bit, both of these two lines are hte W^X detection
            "writable": bool(sec.Characteristics & 0x80000000),
        })
        
    imports = {}
    
    #does this object have an import table
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            
            dll = entry.dll.decode("ascii", errors="replace").lower()
            
            #function names keep their case, CreateFileW is the real symbol
            imports[dll] = [imp.name.decode("ascii") for imp in entry.imports if imp.name]
            
    ts = pe.FILE_HEADER.TimeDateStamp
    return {
        "timestamp": ts,
        
        "timestamp_iso": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
        
        "sections": sections,
        
        "imports": imports,
    }
    
