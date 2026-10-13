# Merkle Mountain Range (MMR)

A SHA-256 append-only accumulator with independently verifiable inclusion and append-only consistency proofs. The repository also retains its earlier threshold-based telemetry, HMAC audit trail, batch CLI, and FastAPI endpoints. **The telemetry subsystem is distinct from the MMR cryptographic implementation.**

## Browser application

Open the GitHub Pages application when deployment has been enabled, or run the static application locally:

~~~bash
python -m http.server 8080 --directory web
~~~

Open http://127.0.0.1:8080. Append UTF-8 leaves, select a leaf to generate an inclusion proof, alter the leaf or JSON proof to test rejection, and generate a consistency proof between checkpoints. Export either proof as JSON. Computation uses the browser's built-in Web Crypto SHA-256; no Python interpreter, backend, external API, accounts, or uploaded data are needed. Data is stored only in tab memory and disappears on reload.

Browser requirements: a current Chromium, Firefox, or Safari browser with Web Crypto and JavaScript modules. Use HTTPS or localhost (secure contexts). The browser demo limits input to **1,024 leaves** and **8 KiB per leaf**.

## Python library

Install in a Python 3.10+ environment:

~~~bash
python -m pip install -e .
~~~

~~~python
from merkle_mountain_range.mmr import MerkleMountainRange

mmr = MerkleMountainRange()
mmr.append("alpha")
mmr.append("beta")
trusted_root = mmr.root

proof = mmr.inclusion_proof(0)
assert MerkleMountainRange.verify_inclusion("alpha", proof, trusted_root)
assert not MerkleMountainRange.verify_inclusion("changed", proof, trusted_root)

old = MerkleMountainRange()
old.append("alpha")
extension = mmr.consistency_proof(old.size)
assert MerkleMountainRange.verify_consistency(old.root, trusted_root, extension)
~~~

Command-line root and proofs:

~~~bash
merkle-mountain-range-mmr mmr --leaf alpha --leaf beta --leaf gamma --prove-index 1 --consistency-from 2
# Also supported: python cli.py mmr --leaf alpha --leaf beta
~~~

### Hashing protocol

The implementation defines its own deterministic serialization; it is **not automatically interoperable** with Ethereum, Grin, or other MMR protocols.

| Component | SHA-256 input |
| --- | --- |
| Leaf | `0x00 || UTF8(leaf)` |
| Internal parent | `0x01 || left_digest || right_digest` |
| Peak bagging | `0x02 || left_peak || right_accumulator` (right to left) |
| Empty MMR root | `SHA256(0x03)` |

Roots are lowercase 64-character hex strings. The peaks are maximal perfect binary trees in left-to-right order. Inclusion proofs include the authentication path and ordered peak hashes and require an **independently trusted root**. Their size is logarithmic in leaf count. Consistency proofs provide old peak hashes and all appended leaf hashes; proof size is **O(number of newly appended leaves)**, not logarithmic. This protocol is an educational/reference implementation; it has not undergone an external cryptographic audit.

## Legacy telemetry and REST API

Install optional API dependencies:

~~~bash
python -m pip install -e ".[api]"
python cli.py audit --task-id T-01 --target KEY-01 --primary 28.5 --secondary 14.2 --critical
python cli.py batch -i sample.csv -o results.csv
python cli.py verify-audit
python cli.py serve --host 127.0.0.1 --port 8000
~~~

The local API serves the browser explorer at **http://127.0.0.1:8000/** when run from the repository checkout. Existing API routes include `GET /health`, `GET /metrics` (JSON counters), `POST /api/audit`, `POST /api/chat`, and `GET /api/audit/logs`. The telemetry subsystem applies configurable threshold-like rules, not a medical or cryptographic standards-conformance engine; its chat provider is a deterministic mock, not an external model integration.

CSV batch input has the fields `task_id,target_identifier,primary_metric,secondary_metric,is_critical_flag,status_descriptor`. The critical flag recognizes `true/false`, `yes/no`, or `1/0` (case-insensitive). Malformed flags raise an error rather than being silently treated as true.

### Security and data handling

- The browser MMR explorer performs **no outbound data transfer** and does not persist leaves or keys.
- HMAC telemetry logs are **in-memory**; for controlled deployments set `AUDIT_SECRET_KEY` to a securely generated, private value. Without it, a random process-local key is generated, and old logs cannot be verified after restart. Logs are not a substitute for a persistent audited ledger.
- The legacy PHI guard uses simple regular expressions. **It is not comprehensive de-identification, regulatory compliance verification, or a guarantee that protected data cannot escape.** Avoid inputting patient data.
- The development REST API does not implement authentication. Do not expose it publicly without an authentication and access-control proxy.

Docker / Compose (the Compose port binds to loopback):

~~~bash
export AUDIT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
docker compose up --build
~~~

## Verification

~~~bash
python -m pip install -e ".[api,test]"
python -m pytest -q
node --check web/app.mjs
node --check web/mmr.mjs
node tests/mmr_web.mjs
~~~

CI covers Python 3.10–3.13 and Node 22. The `.github/workflows/pages.yml` workflow deploys `web/` from `master` after GitHub Pages is configured for GitHub Actions. The app uses no Pyodide: native JavaScript/Web Crypto is lighter and avoids runtime dependency downloads.

## License

MIT — see [LICENSE](LICENSE).
