# Tier 1 Security Monitoring — GitHub vs BadSSL

A Python 3.10+ **standard-library-only** passive monitoring prototype for an academic placement. Tests GitHub and purpose-built BadSSL endpoints. Run only against domains you are authorized to assess; default requests are limited to public HEAD and TLS handshakes.

## Run locally

```bash
python monitor.py
python monitor.py --targets github.com badssl.com expired.badssl.com self-signed.badssl.com wrong.host.badssl.com
```

Reports are written to `reports/scan_YYYYMMDDTHHMMSSZ.json` and `.md`.

## GitHub Actions

Push the contents of this folder to a repository. Go to **Actions → Tier 1 Weekly Website Security Scan → Run workflow**. The workflow also runs Mondays at 09:00 UTC. Download the `tier1-security-reports` artifact after the run.

## What it checks

- HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and frame protection (X-Frame-Options or CSP frame-ancestors)
- Verified TLS certificate expiry and days remaining; attempts unverified expiry extraction on intentionally invalid certs
- TLS 1.2 and TLS 1.3 support with negotiated cipher per successful handshake
- Direct HTTP → HTTPS redirect (not multi-hop)
- Timestamped JSON and Markdown reports

## Limitations

- TLS 1.0/1.1 and exhaustive cipher enumeration are **not** implemented; TLS 1.2/1.3 handshakes only.
- Invalid certificates can prevent fetching HTTPS headers; this is recorded as **not verified**, not **missing**.
- Network errors, firewalls, DNS, and HEAD rejection can affect results.
- A missing header is a configuration observation, not automatically an exploitable vulnerability.
- GitHub Actions scheduled workflows may be delayed or disabled on inactive repositories.
- BadSSL's root domain is not inherently insecure; test endpoints demonstrate specific failures.
- No live scan results are included. Run the workflow and use its artifacts as evidence.
