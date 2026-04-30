import os
import sys
from pathlib import Path

# Avoid live LangGraph / LLM calls in unit tests (enable explicitly in integration tests).
os.environ.setdefault("USE_LANGGRAPH_RUNTIME", "false")

# Ensure repository root is on sys.path when tests run from any cwd.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
