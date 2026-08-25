# okfhub/registry

Public registry of [OKF](https://github.com/GoogleCloudPlatform/knowledge-catalog) bundle manifests for [`okfhub-cli`](https://github.com/okfhub/okfhub).

Each manifest lives at `<namespace>/<name>.json` (e.g. `io.github.google/ga4-ecommerce.json`) and is served over `raw.githubusercontent.com` (CDN-backed, effectively unlimited). The CLI resolves `okfhub add <org>/<bundle>` to `<namespace>/<name>.json` here.

## Bundles

No bundle list is maintained here — a hand-kept copy drifts from the manifests (this table once listed 1 of 5). The always-current index lives in two places:

- **[okfhub.io](https://okfhub.io)** — the browsable registry
- this repo's namespace directories — one `<name>.json` manifest per bundle (e.g. [`io.github.google/`](io.github.google/))
