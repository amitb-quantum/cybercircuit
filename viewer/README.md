# Cyber-Circuit evidence viewer

The viewer shows published bundles and their recorded independent verifier results with and without receipts. The two views use the same evidence and different verification inputs.

Build the exported viewer with Node.js and npm:

```sh
cd frontend
npm ci
npm run build:demo
```

Serve `frontend/dist-demo/` with a static HTTP server. The viewer loads its own assets and uses the embedded recordings for all interactions.

To regenerate the recordings from public inputs, use Python 3.11+, curl, sha256sum and the pinned public verifier. Run these commands from the viewer root:

```sh
bash demo/fetch-fixtures.sh
python3 demo/precompute.py --verifier /path/to/cybercircuit-verify \
  --verifier-version 0.1.0 --verifier-commit 6f720a6429341b4c56f4290f80f86769d3eca366
```

See [Data sources](DATA-SOURCES.md) for the public contracts and the origin of the verdicts.
