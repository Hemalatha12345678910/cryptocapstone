"""
Pytest Configuration and Namespace Bridge
Ensures local project packages (including local cryptography modules)
are cleanly discoverable by pytest runners and third-party tools.
"""

import sys
import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Extend cryptography.__path__ with local cryptography package directory
try:
    import cryptography
    local_crypto_dir = str(ROOT_DIR / "cryptography")
    if local_crypto_dir not in cryptography.__path__:
        cryptography.__path__.insert(0, local_crypto_dir)
except Exception:
    pass

