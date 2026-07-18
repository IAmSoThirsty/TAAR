"""Operating-system-backed confinement for TAAR external commands.

The registry describes authority; this module turns that authority into an
execution boundary.  External commands fail closed when no supported sandbox
backend is available.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence