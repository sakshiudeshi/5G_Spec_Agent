"""Put fiveg_specifier/ on sys.path so the tests import the scripts flat."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
