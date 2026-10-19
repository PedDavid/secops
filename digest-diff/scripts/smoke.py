#!/usr/bin/env python3
"""Exercise a deployed digest-diff service with real public image digests."""
import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--url", default="http://127.0.0.1:8080")
parser.add_argument("--old", default="docker.io/library/alpine@sha256:3c81aa9a3d770b316568f4499e30461a5cd3fbd7180bd89e28e34894c7845832")
parser.add_argument("--new", default="docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764")
args = parser.parse_args()
query = urllib.parse.urlencode({"old": args.old, "new": args.new})


def request(path, method="GET"):
    req = urllib.request.Request(args.url.rstrip("/") + path, method=method)
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read(), response.headers


deadline = time.monotonic() + 60
while True:
    try:
        body, _ = request("/healthz")
        assert body == b"ok\n", body
        break
    except (OSError, AssertionError):
        if time.monotonic() >= deadline:
            raise
        time.sleep(1)

request("/jobs?" + query, "POST")
deadline = time.monotonic() + 960
while True:
    body, _ = request("/jobs?" + query)
    state = json.loads(body)
    if state["state"] == "completed":
        break
    if state["state"] == "failed":
        raise RuntimeError(state["error"])
    if time.monotonic() >= deadline:
        raise TimeoutError("Comparison did not complete within 16 minutes")
    time.sleep(2)

body, _ = request("/diff.json?" + query)
report = json.loads(body)
assert report["scan"]["platform"] == "linux/amd64", report["scan"]
assert report["scan"]["database"]["valid"] is True, report["scan"]
assert report["scan"]["database_id"], report["scan"]
for field in ("added", "removed", "changed"):
    assert isinstance(report[field], list), field
for field in ("introduced", "resolved", "persisting"):
    assert isinstance(report["vulnerabilities"][field], list), field
body, _ = request("/diff.json?" + query)
assert json.loads(body)["scan"]["scanned_at"] == report["scan"]["scanned_at"], "Fresh report not reused"
body, headers = request("/badge?" + query)
assert b"<svg" in body and b"vulnerabilities" in body, body
assert "immutable" not in headers.get("Cache-Control", ""), headers
body, _ = request("/diff?" + query)
assert b"Vulnerability changes" in body and b"Scan details" in body, "Incomplete HTML report"
print(json.dumps({"result": "passed", "scan": report["scan"], "finding_counts": {
    key: len(value) for key, value in report["vulnerabilities"].items()
}}, indent=2))
