# okfhub/registry

Public registry of [OKF](https://github.com/GoogleCloudPlatform/knowledge-catalog) bundle manifests for [`okfhub-cli`](https://github.com/okfhub/okfhub).

Each manifest lives at `<namespace>/<name>.json` (e.g. `io.github.google/ga4-ecommerce.json`) and is served over `raw.githubusercontent.com` (CDN-backed, effectively unlimited). The CLI resolves `okfhub add <org>/<bundle>` to `<namespace>/<name>.json` here.

## Bundles

| Namespace | Name | Source |
|-----------|------|--------|
| `io.github.google` | `ga4-ecommerce` | `GoogleCloudPlatform/knowledge-catalog` @ `okf/bundles/ga4` |
