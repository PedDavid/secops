#!/usr/bin/env python3
"""Smoke a demo instance (no external registries required)."""
import argparse
import json
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--url', default='http://127.0.0.1:8080')
parser.add_argument('--ops', default='http://127.0.0.1:9090')
parser.add_argument('--live', action='store_true', help='Scan real pinned public images instead of demo fixtures')
args = parser.parse_args()

class Tokens(HTMLParser):
    token = None
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'input' and attrs.get('name') == '_csrf':
            self.token = attrs.get('value')

def request(url, **kwargs):
    with urllib.request.urlopen(urllib.request.Request(url, **kwargs), timeout=30) as r:
        return r.read().decode()

for _ in range(60):
    try:
        assert request(args.ops + '/readyz') == 'ready\n'
        break
    except OSError:
        time.sleep(1)
else:
    raise RuntimeError('Service did not become ready')

html = request(args.url + '/')
p = Tokens(); p.feed(html)
assert p.token, 'No CSRF token in page'
images = {'old': 'alpine@sha256:' + 'c'*64, 'new': 'alpine@sha256:' + 'd'*64}
if args.live:
    images = {
        'old': 'registry-1.docker.io/library/alpine@sha256:3c81aa9a3d770b316568f4499e30461a5cd3fbd7180bd89e28e34894c7845832',
        'new': 'registry-1.docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764'
    }
query = urllib.parse.urlencode(images)
request(args.url + '/jobs?' + query, method='POST', headers={
    'Origin': args.url, 'X-CSRF-Token': p.token
})
for _ in range(480 if args.live else 60):
    job = json.loads(request(args.url + '/jobs?' + query))
    if job['state'] == 'completed':
        break
    if job['state'] == 'failed':
        raise RuntimeError(job['error'])
    time.sleep(2 if args.live else .2)
else:
    raise RuntimeError('Comparison did not complete')
report = json.loads(request(args.url + '/diff.json?' + query))
assert report['scan']['platform'] == 'linux/amd64'
assert set(report['vulnerabilities']) == {'introduced', 'resolved', 'persisting'}
if not args.live:
    assert report['vulnerabilities']['resolved']
else:
    assert report['scan']['database']['valid'] is True
html = request(args.url + '/diff?' + query)
if not args.live:
    assert 'https://www.cve.org/CVERecord?id=' in html
assert 'every 2s' not in html, 'Completed page should stop polling'
metrics = request(args.ops + '/metrics')
assert 'digest_diff_comparisons_completed_total' in metrics
print('PASS: readiness, CSRF submission, completion, report, advisory links, metrics')
