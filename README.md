# GopherTLS Python (curl_cffi)

Python port of the Go `GopherTLS-API` with API-contract parity for `POST /go/pher`.

## Install

```bash
cd python
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Install (Windows)

PowerShell:

```powershell
cd python
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Command Prompt (cmd):

```bat
cd python
py -3 -m venv .venv
.venv\Scripts\activate.bat
pip install -e .
```

## Run (Windows)

```powershell
python -m gophertls_api.main
```

## Run

Create `.env` in repository root or `python/`:

```env
SERVER_HOST=0.0.0.0
SERVER_PORT=42690
```

Start service:

```bash
python -m gophertls_api.main
```

## API

- Endpoint: `POST /go/pher`
- Required headers: `x-tls-url`, `x-tls-method`, `x-tls-profile`, `x-tls-header-order`, `x-tls-pseudo-order`
- Optional headers: `x-tls-proxy`, `x-tls-timeout`, `x-tls-follow-redirects`, `x-tls-force-h1`, `x-tls-insecure-skip-verify`, `x-tls-with-random-extension-order`

## Profile Mapping

The Go `tls-client` profile header is mapped in `src/gophertls_api/profiles/map.py`.

| Go style | curl_cffi impersonate |
|---|---|
| `firefox_147` | `firefox144` |
| `chrome_142` | `chrome142` |
| `safari_184` | `safari184` |
| `edge_101` | `edge101` |

Raw `curl_cffi` targets (e.g. `chrome136`) are also accepted directly.

## Parity Notes

- `x-tls-pseudo-order`: applied via `HTTP2_PSEUDO_HEADERS_ORDER`.
- `x-tls-header-order`: preserved best-effort from incoming header order.
- `x-tls-with-random-extension-order`: mapped to `ExtraFingerprints(tls_permute_extensions=...)`.
- Fingerprint output is close but not bit-identical to bogdanfinn/tls-client.
