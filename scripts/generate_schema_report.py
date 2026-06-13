import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.llm.schema_inspector import main

if __name__ == "__main__":
    argv = sys.argv[1:]
    raise SystemExit(main())
 
 
 
if __name__ == "__main__":
    argv = sys.argv[1:]
    if not any(a.startswith("--target") for a in argv) and not any(
        a.startswith("--endpoint") for a in argv
    ):
        argv = ["--target", "public", *argv]
    raise SystemExit(main(argv))
 