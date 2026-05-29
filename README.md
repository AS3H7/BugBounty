# BookBeat Bug Bounty — Testing Toolkit (YesWeHack)

> **Authorized testing only**, under BookBeat's YesWeHack program. This toolkit is built to **respect the program's Rules of Engagement** — especially the bans on automated scanners / high-traffic tooling and the mandatory ` yeswehack ` User-Agent.

---

## ⚠️ Read This First

BookBeat's rules are strict. This toolkit enforces them, but you must too:

1. **Every request carries the ` yeswehack ` User-Agent** — or you get blocked. `bb-request.sh` and friends inject it automatically.
2. **No automated scanners / no high-traffic tools.** Recon here is **passive only** (third-party archives). Active testing is **manual, one request at a time, rate-limited**.
3. **No DoS, no service degradation.**
4. **Never copy/leak/modify user data.** If you reach another user's data, stop, take minimal proof, report.
5. **Use YesWeHack email aliases** for registration and contact forms.
6. **No public disclosure.**

See **`scope.md`** for the full in/out-of-scope reference.

---

## Repository Layout

```
BugBounty/
├── README.md                  # You are here
├── scope.md                   # In/out-of-scope assets, rules, bug classes
├── bookbeat/
│   ├── config.sh              # Central config: UA, headers, hosts, rate limit, scope guard
│   ├── api_login.sh           # Authenticate (your own account) -> cache token
│   ├── bb-request.sh          # Safe curl wrapper (enforces UA + scope guard + delay)
│   ├── idor_check.sh          # Two-account IDOR/BAC test harness (safe, no harvesting)
│   ├── passive_recon.sh       # PASSIVE recon (third-party archives only)
│   ├── METHODOLOGY.md         # Where the bugs are + how to hunt them
│   └── output/                # Recon output (gitignored)
├── reports/
│   └── TEMPLATE.md            # Report structure for YesWeHack submissions
└── targets/                   # Your per-endpoint notes
```

---

## Quick Start

### 1. Set your credentials (in your shell — never commit)
```bash
export BB_USERNAME="your-ywh-alias@example.com"
export BB_PASSWORD="your-password"
```

### 2. Passive recon (safe — no traffic to BookBeat)
```bash
cd bookbeat
./passive_recon.sh
# Review output/passive_*/SUMMARY.md, api_endpoints.txt, idor_candidates.txt
```

### 3. Authenticate
```bash
./api_login.sh                                   # primary account -> /tmp/.bb_token
BB_TOKEN_FILE=/tmp/.bb_A ./api_login.sh          # account A (for IDOR)
export BB_USERNAME=B@alias BB_PASSWORD=...; BB_TOKEN_FILE=/tmp/.bb_B ./api_login.sh   # account B
```

### 4. Manual, surgical requests (UA + scope guard + rate limit enforced)
```bash
./bb-request.sh GET https://api.bookbeat.com/api/my/books --auth --verbose
./bb-request.sh GET "https://search-api.bookbeat.com/search?q=test" --verbose
```

### 5. Test an IDOR candidate safely
```bash
# Find one of YOUR OWN resource IDs as account A, then:
./idor_check.sh https://api.bookbeat.com/api/my/bookmarks/<your_A_id>
```

### 6. Write up findings
```bash
cp reports/TEMPLATE.md reports/idor-bookmarks.md   # then fill it in
```

---

## Dependencies

Minimal, by design (we're not running scanners):
- `curl`, `jq` (required)
- `gau`, `waybackurls`, `unfurl` (optional — passive recon; if absent, the Wayback CDX API fallback still works)

Install the optional passive tools:
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/unfurl@latest
```

---

## Methodology Summary

The scope is narrow and API-heavy. Aim, in order:

1. **IDOR / BAC** — other users' library, profile, payment, reading progress
2. **Business logic** — premium content without paying, subscription/tier abuse, family-seat abuse
3. **Auth / privilege escalation** — token scoping across the 3 APIs, JWT tampering
4. **Injection** — search-api is the prime SQLi/XSS surface
5. **SSRF / XXE / LFI** — any fetch/import/upload (blind SSRF w/o PoC = out)
6. **CORS / CSRF / open redirect** — only with real impact

Full details: **`bookbeat/METHODOLOGY.md`**.

---

## Disclaimer

For **authorized** participation in BookBeat's YesWeHack bug bounty program only.
Follow the program rules and the law. Test only your own accounts. Never access
data that isn't yours.
