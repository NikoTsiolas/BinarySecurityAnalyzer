"""SHA256 and MD5 of the target file.

MD5 is only here as a lookup key for older threat intel — SHA256 is the
one we trust.
"""

import hashlib
from pathlib import Path

# read big installers in pieces instead of loading the whole file into RAM. 1MiB easier to read as this than whole number
CHUNK_SIZE = 1024 * 1024


def hash_file(path: Path) -> dict[str, str]:
    """Hex SHA256 and MD5 of the file, computed in a single pass."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()

    with path.open("rb") as f:
        #f.read returns up to 1MiB, a full chunk mid file, partial chunk at the end, and empty bytes once its exhausted
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
            md5.update(chunk)

    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}
