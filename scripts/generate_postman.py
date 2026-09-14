#!/usr/bin/env python3
"""
Regenerate the Postman collection from a running CHAKRAVYUH server.

This script fetches /postman.json from the live server and writes it to
postman/collection.json. Run it whenever the API changes so the versioned
collection stays in sync.

Usage:
    # 1. Start the server
    cargo run --release -- serve --config configs/config.example.yaml

    # 2. Run this script
    python3 scripts/generate_postman.py

    # 3. Commit the updated collection.json
    git add postman/collection.json
    git commit -m "postman: regenerate collection from server"
"""

import json
import sys
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError

BASE_URL = "http://localhost:8443"
OUTPUT_PATH = Path(__file__).parent.parent / "postman" / "collection.json"


def main() -> int:
    url = f"{BASE_URL}/postman.json"
    print(f"Fetching {url} ...")
    try:
        with urlopen(url, timeout=10) as resp:
            if resp.status != 200:
                print(f"ERROR: server returned {resp.status}", file=sys.stderr)
                return 1
            collection = json.loads(resp.read())
    except URLError as e:
        print(f"ERROR: cannot connect to {url}", file=sys.stderr)
        print(f"  {e}", file=sys.stderr)
        print("  Is the server running? Start it with:", file=sys.stderr)
        print("  cargo run --release -- serve --config configs/config.example.yaml", file=sys.stderr)
        return 1

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(collection, indent=2) + "\n")
    print(f"Wrote {OUTPUT_PATH}")
    print(f"  collection name: {collection['info']['name']}")
    items = collection.get("item", [])
    print(f"  endpoint count:  {len(items)}")
    variables = collection.get("variable", [])
    print(f"  variables:       {len(variables)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
