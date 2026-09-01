#!/usr/bin/env python3
"""Flask API entrypoint."""

import argparse

from api.app import create_app

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    # Loopback by default: the API is unauthenticated and each scan spends LLM credits.
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    args = p.parse_args()
    app = create_app()
    # threaded=True so long-running SSE scans do not block other API clients on the dev server.
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
