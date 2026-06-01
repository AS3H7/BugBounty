# WHOOP Bug Bounty — Scope Reference

## Platform: HackerOne

## In-Scope Targets (All Critical Severity, Eligible)

| Target | Type | Acceptance Rate |
|--------|------|-----------------|
| `api.prod.whoop.com` | Domain (REST API) | 34% (14 reports) |
| `app.whoop.com` | Domain (Web App) | 15% (6 reports) |
| `shop.whoop.com` | Domain (E-commerce) | 10% (4 reports) |
| `join.whoop.com` | Domain (Onboarding) | 5% (2 reports) |
| `com.whoop.iphone` | iOS App | 0% (0 reports) |
| `com.whoop.android` | Android App | 2% (1 report) |
| WHOOP 4.0 STRAP | Hardware | 0% (0 reports) |
| WHOOP 5.0/MG STRAP | Hardware | 0% (0 reports) |

## Out-of-Scope / Ineligible

| Target | Reason |
|--------|--------|
| `okta.whoop.com` | Report to Okta's program |
| Support Systems (Live Chat, Intercom, Iterable, Salesforce) | Banned if you flood queues |
| Credit/Debit Card Testing | Strictly prohibited |
| Azure AD, Google Drive, Link Sharing Websites | Internal tools |
| Sentry, Datadog, Segment, Amplitude | Metrics/reporting vendors |

## Out-of-Scope Bug Classes

- XSS without demonstrated impact
- Clickjacking without sensitive actions
- Unauthenticated/logout/login CSRF
- Subdomain/dangling DNS takeover without impact
- Missing SSL/TLS best practices
- Known vulnerable libraries without working PoC
- CSV injection without demonstrated vuln
- MITM or physical access attacks
- Brute force from WayBack Machine only
- S3 buckets with "whoop" that don't prove WHOOP ownership

## Key Program Rules

- No credentials provided — must purchase/trial WHOOP
- No destructive actions (writes/edits/deletes on others' accounts)
- No random API fuzzing — methodical and reproducible only
- No social engineering
- Must demonstrate CIA impact
- One vuln per report unless chaining
- Only test with accounts you own

## Known Infrastructure (From Recon)

| Subdomain | Technology | Notes |
|-----------|-----------|-------|
| `api.prod.whoop.com` | Cloudflare, Kubernetes, Ory Hydra (OAuth2) | Primary API |
| `api.dev.whoop.com` | Cloudflare, Kubernetes, Ory Hydra | Dev environment (live!) |
| `api-7.whoop.com` | Cloudflare | Alternative API server |
| `id.whoop.com` | Cloudflare (bot challenge) | Identity/SSO service |
| `developer.whoop.com` | Cloudflare | Developer portal & docs |
| `mxp.dev.whoop.com` | Unknown (found in CSP) | Internal — discovered via CloudFront CSP |
| `mxp.prod.whoop.com` | Unknown (found in CSP) | Internal — discovered via CloudFront CSP |
| `ddishpycw9cpz.cloudfront.net` | S3 + CloudFront, AngularJS | Legacy WHOOP web app |
| `whoop-inc.myshopify.com` | Shopify | Backend e-commerce |
