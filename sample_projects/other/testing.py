"""
Python Import Testing Tool
Demonstrates multiple import styles, syntax variations, and edge cases.
"""

# 1. Standard absolute import
import os
import sys

# 2. Aliased absolute import
import math as mathematics

# 3. Multiple absolute imports on a single line
import time, platform, gc

# 4. From-style import of a single attribute
from datetime import datetime

# 5. From-style import of multiple attributes
from collections import namedtuple, OrderedDict, defaultdict

# 6. From-style import with an alias
from json import dumps as json_stringify

# 7. Parenthesized multiple from-style imports (useful for long lines)
from os.path import (
    abspath,
    dirname,
    join,
    exists
)

# 8. Star import (imports everything into global namespace; use with caution)
from random import *

# 9. Importing a deeply nested submodule
import xml.etree.ElementTree as ET

# 10. Conditional imports based on a runtime flag
if sys.platform.startswith("win"):
    import ctypes
else:
    import posix as ctypes  # Mock fallback for non-Windows testing

# 11. Optional third-party imports wrapped in try/except blocks
try:
    import requests
    from bs4 import BeautifulSoup as BS
except ImportError:
    requests = None
    BS = None

try:
    import numpy as np
    import pandas as pd
except ImportError:
    np = None
    pd = None

# 12. Local/Relative imports (simulated for directory structures)
try:
    from . import local_package
    from ..parent_dir import parent_module
    from .sibling import ChildClass as LocalChild
except (ImportError, ValueError):
    # Fails if run as a standalone script outside a package context
    pass


def execute_dynamic_imports():
    """Demonstrates imports scoped inside functions and dynamic strings."""
    
    # 13. Function-scoped local import (lazy loading)
    import hashlib
    print(f"[Local Import] Hash algorithm list length: {len(hashlib.algorithms_guaranteed)}")

    # 14. Dynamic string import using the built-in __import__ function
    module_name = "csv"
    csv_module = __import__(module_name)
    print(f"[Dynamic __import__] Loaded: {csv_module.__name__}")

    # 15. Dynamic string import using importlib (preferred modern style)
    import importlib
    sqlite = importlib.import_module("sqlite3")
    print(f"[Dynamic Importlib] Loaded: {sqlite.__name__}")


def verify_imports():
    """Executes code from the imported tools to verify they work."""
    print("--- Verification Test ---")
    print(f"OS Path: {abspath('.')}")
    print(f"Current Year: {datetime.now().year}")
    print(f"Math Pi Alias: {mathematics.pi}")
    print(f"JSON Dump Alias: {json_stringify({'test': True})}")
    print(f"Random Star Import (randint): {randint(1, 100)}")  # From star import
    
    # Check if optional third-party components loaded
    print(f"Requests Available: {requests is not None}")
    print(f"NumPy Available: {np is not None}")


if __name__ == "__main__":
    verify_imports()
    execute_dynamic_imports()
