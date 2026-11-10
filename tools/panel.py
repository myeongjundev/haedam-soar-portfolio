"""Start the personal loopback control panel; no third-party runtime dependencies."""
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'services/lab-panel'))
from lab_panel.server import main

if __name__=='__main__':
    main()
