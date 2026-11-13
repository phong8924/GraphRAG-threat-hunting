"""Serve one-question interactive RAG/GraphRAG, offline unless --live is explicit."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/interactive/dashboard_v1.json")
    parser.add_argument("--manifest", type=Path, default=ROOT / "configs/interactive/runtime_manifest_v3.json")
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/demo" / datetime.now(timezone.utc).strftime("interactive-%Y%m%dT%H%M%S%fZ"))
    parser.add_argument("--port", type=int, default=8032)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--max-requests", type=int, default=0)
    args = parser.parse_args()
    if (args.live and not 1 <= args.max_requests <= 6) or (not args.live and args.max_requests != 0):
        parser.error("Use offline defaults, or explicit --live --max-requests <1..6>")
    from scripts.interactive_runtime import InteractiveSession, create_interactive_app
    import uvicorn
    try:
        session = InteractiveSession(args.output, config_path=args.config, pin_path=args.manifest,
                                     live=args.live, max_requests=args.max_requests)
    except OSError as exc:
        parser.exit(1, f"persistence_error: startup; {type(exc).__name__}; errno={exc.errno}\n")
    except Exception as exc:
        parser.exit(1, f"Interactive startup failed: {type(exc).__name__}: {exc}\n")
    print(f"INTERACTIVE {'LIVE' if args.live else 'OFFLINE'}; cap={args.max_requests}; no retry/fallback; NOT benchmark certified", flush=True)
    print(f"http://127.0.0.1:{args.port}/", flush=True)
    uvicorn.run(create_interactive_app(session), host="127.0.0.1", port=args.port, log_level="info")


if __name__ == "__main__":
    main()
