# Double-click this on Windows to open Wisp (no console window).
# Keep it in the same folder as wisp.py.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wisp  # noqa: E402

wisp.main([])
