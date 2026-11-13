"""Serve the current resizable dashboard with an independently pinned LLM profile."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
for name in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY", "HF_HUB_DISABLE_IMPLICIT_TOKEN"):
    os.environ[name] = "1"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/interactive/dashboard_live_v3.json")
    parser.add_argument("--manifest", type=Path, default=ROOT / "configs/interactive/runtime_manifest_live_v2.json")
    parser.add_argument("--port", type=int, default=8034)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--max-requests", type=int, default=0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if (args.live and not 1 <= args.max_requests <= 6) or (not args.live and args.max_requests != 0):
        parser.error("Offline defaults or explicit --live --max-requests 1..6 required")
    from scripts.current_interactive_runtime import CurrentInteractiveSession, create_current_app, verify_current_manifest
    import uvicorn
    try:
        verify_current_manifest(args.config, args.manifest)
        if args.check:
            print("CURRENT_INTERACTIVE_READY; exact source/build/consumer/model/environment bindings; 0 LLM calls")
            return
        output = args.output or ROOT / "outputs/demo" / datetime.now(timezone.utc).strftime("current-interactive-%Y%m%dT%H%M%S%fZ")
        session = CurrentInteractiveSession(output, config_path=args.config, pin_path=args.manifest, live=args.live, max_requests=args.max_requests)
    except Exception as exc:
        parser.exit(1, f"Current interactive startup blocked: {type(exc).__name__}: {exc}\n")
    print(f"CURRENT UI {'LIVE' if args.live else 'OFFLINE'} cap={args.max_requests}; no retry/fallback; http://127.0.0.1:{args.port}/", flush=True)
    uvicorn.run(create_current_app(session), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
