# Tesla Bug Bounty — Scope Reference

## In-Scope Domains

| Domain Pattern | Notes |
|---|---|
| `*.tesla.com` | Main web properties (Akamai CDN, Drupal, Varnish, CloudFlare) |
| `*.teslamotors.com` | Legacy domain, still active |
| `*.tesla.cn` | China-specific properties (Akamai, CloudFlare, Drupal) |
| `*.tesla.services` | Services infrastructure |
| `*.solarcity.com` | Solar/energy acquisition |
| `*.teslainsuranceservices.com` | Insurance vertical |
| Any host verified to be owned by Tesla Motors Inc. | Domains, IP space, etc. |
| Official Tesla iOS app | https://apps.apple.com/us/app/tesla/id582007913 |
| Official Tesla Android app | https://play.google.com/store/apps/details?id=com.teslamotors.tesla |

## Out-of-Scope Hosts (DO NOT TEST)

- `employeefeedback.tesla.com`
- `energysupport.tesla.com`
- `engage.tesla.com` / `*.engage.tesla.com`
- `feedback.tesla.com` / `feedback.teslamotors.com`
- `ir.tesla.com` / `ir.teslamotors.com`
- `mkto.teslamotors.com`
- `shop.eu.teslamotors.com`
- `service.tesla.com/docs/*` / `service.tesla.cn/docs/*`
- Any acquisition domains (e.g., `maxwell.com`)
- Any third-party hosted sites
- Superchargers and related infrastructure

## In-Scope Bug Classes (Prioritized)

| Priority | Class | Expected Payout |
|---|---|---|
| 1 | IDOR / Broken Access Control | P1–P2 ($500–$10k) |
| 2 | SSRF (cloud metadata pivot) | P1–P2 |
| 3 | Auth/Authz logic & Account Takeover (non-MFA) | P1–P2 |
| 4 | SQL Injection / Command Injection | P1–P2 |
| 5 | Sensitive data exposure / cross-tenant leakage | P1–P3 |
| 6 | Stored XSS with real impact (ATO chain) | P2–P3 |
| 7 | Business logic flaws (price tampering, step-skip) | P2–P3 |

## Out-of-Scope Bug Classes (DO NOT REPORT)

- Tesla account MFA issues
- WAF bypass (standalone)
- Open redirects / lack of security speedbump
- Self-XSS
- Text injection
- Email spoofing (SPF/DKIM/DMARC/From)
- Clickjacking (standalone)
- CSRF on non-integrity actions (login/logout, contact forms)
- Missing Secure/HTTPOnly cookie flags
- Lack of rate limiting
- Login/forgot-password brute force, account lockout, weak password policy
- HTTPS mixed content
- Username/email enumeration via error messages
- Missing HTTP security headers
- TLS/SSL issues (BEAST, BREACH, bad ciphers, expired certs)
- Denial of Service
- Out-of-date software (unless PoC of exploitation)
- Known-vulnerable components (unless PoC of exploitation)
- Internal IP disclosure
- Non-sensitive file disclosure (README, robots.txt, .gitignore, WSDL, pprof)
- Descriptive error messages / stack traces / path disclosure
- Fingerprinting / banner disclosure on common services
- Physical attacks

## Rules of Engagement Reminders

1. **Own account only.** Use two of your own accounts to demonstrate cross-account bugs.
2. **Stop & report within 24h** if you find access to another user's data — do NOT pull the data.
3. **No brute force / DoS** without prior written approval.
4. **No automated form spam** — respect rate limits organically.
5. **Register with** `username@bugcrowdninja.com` email.
6. **Delete any inadvertently accessed data**, prove deletion, confirm to Tesla.
