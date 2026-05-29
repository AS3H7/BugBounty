# BookBeat Bug Bounty — Scope Reference (YesWeHack)

Audiobook/eBook subscription service. Narrow scope — **only the assets listed below are in scope. Everything else (all other domains/subdomains) is OUT of scope.**

## In-Scope Assets

| Asset | Type | Asset Value |
|---|---|---|
| `https://www.bookbeat.com` | Web application | Medium |
| `https://api.bookbeat.com` | API | Medium |
| `https://search-api.bookbeat.com` | API | Medium |
| `edge.bookbeat.com` | API | Medium |
| Android app — `com.bookbeat.android` | Mobile | Medium |
| iOS app — `id1056652614` | Mobile | Medium |

## Rewards (CVSS-based + business impact)

| Severity | Reward |
|---|---|
| Low | €100 |
| Medium | €300 |
| High | €1,000 |
| Critical | €2,000 |

Duplicate/systemic issues are paid on a sliding scale (1st: 100% … 6th+: 10%).

---

## CRITICAL Hunting Requirements (non-negotiable)

1. **User-Agent must contain ` yeswehack `** on EVERY request. This whitelists your traffic with their security team. **Without it, you get blocked.**
2. **No automated scanners / no high-traffic tooling.** No mass directory brute-force, no aggressive fuzzing, no traffic floods.
3. **No DoS / no service degradation.**
4. **Never leak, copy, modify, or destroy user data.**
5. **Use YesWeHack email aliases** (with keyword "Bug Bounty") for account creation and any contact-form interaction.
6. **No public disclosure** — full, partial, or otherwise.
7. **API authentication:**
   - Route: `POST https://api.bookbeat.com/api/login`
   - Body: `{"username": "<you>", "password": "<you>"}`
   - Headers: `bb-client: BookBeatApp`, `bb-device: api ywh`

---

## Qualifying (In-Scope) Vulnerability Classes — Prioritized

| Priority | Class | BookBeat-specific angle |
|---|---|---|
| 1 | IDOR | Other users' library, profile, payment info, reading progress via API object refs |
| 2 | Horizontal/Vertical Privilege Escalation | Cross-account access; user→admin |
| 3 | Business Logic (real impact) | Free premium content, trial/subscription abuse, family-plan seat abuse |
| 4 | Auth bypass / broken authentication | Token handling across the 3 APIs |
| 5 | SQLi | search-api is a prime candidate |
| 6 | SSRF / LFI / RFI / XXE / XSPA | Any import/fetch/upload feature (NOTE: blind SSRF w/o PoC = out) |
| 7 | XSS (impacting other users) | Stored/reflected with cross-user impact (self-XSS = out) |
| 8 | CORS / CSRF with real security impact | Must show genuine impact |
| 9 | Open Redirect | In scope (but unexploitable header-based = out) |
| 10 | Exposed secrets/credentials | Only on in-scope assets affecting scope |

---

## NON-Qualifying (Out-of-Scope) — DO NOT REPORT

- Broken link / social media hijacking, tabnabbing
- Missing cookie flags, missing security headers (w/o exploit)
- Content/text injection, CSV injection
- Clickjacking / UI redressing
- DoS
- CVEs patched <30 days ago; CVEs/open ports without PoC
- Social engineering
- Autocomplete attribute presence
- Outdated-browser/platform-only issues
- Self-XSS or XSS that can't impact others
- Hypothetical/best-practice findings without PoC
- SSL/TLS issues (expired certs, etc.)
- Unexploitable issues (self-XSS, header-based open redirect)
- MITM / physical-access scenarios
- Low-severity CSRF (logout/login/cart updates)
- Email security records (SPF/DKIM/DMARC)
- Session management (expiration, logout-on-pw-change, concurrent sessions)
- User enumeration (email/alias/GUID/phone)
- Weak password policy
- Spam/flooding (email/SMS/DM)
- Misconfigured public API keys (Google Maps/Firebase/analytics)
- Password reset token via HTTP referer to external services
- Secrets gathered from third-party/out-of-scope assets
- Pre-account-takeover via OAuth
- **GraphQL introspection enabled** (out!)
- Task hijacking, crashing your own app
- Rate-limiting / brute-force / captcha issues
- **Blind SSRF without PoC** (DNS/HTTP pingback, WP XMLRPC)
- Subdomain takeover without full PoC
- Mobile: lack of obfuscation/SSL-pinning/root-detection/anti-debug, rooted/jailbroken-only, obsolete-OS-only, outdated-binary-only, internal DB encryption

---

## Rules of Engagement — Operating Reminders

- **Own accounts only.** Use two of your own accounts (A & B) to demonstrate IDOR/BAC.
- **Stop immediately** if you can reach another user's data — capture minimal proof, do NOT harvest, report it.
- **Throttle everything.** Manual, surgical requests — no scanners.
- **Every request carries the ` yeswehack ` User-Agent.**
- **Register/contact** only with YesWeHack email aliases.
