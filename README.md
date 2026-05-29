# Tesla Bug Bounty — Recon & Testing Toolkit

> **Authorized testing only.** This toolkit is for use against Tesla's public bug bounty program on [Bugcrowd](https://bugcrowd.com/tesla). All testing must follow Tesla's Rules of Engagement. Use your own accounts. Never access other users' data.

---

## Repository Structure

```
BugBounty/
├── README.md                    # You are here
├── scope.md                     # In-scope/out-of-scope targets & bug classes
├── recon/
│   ├── install.sh               # One-command tool installer
│   ├── tesla_recon.sh           # Main recon pipeline (5 phases)
│   ├── endpoint_discovery.sh    # Targeted endpoint & param mining
│   └── wordlists/
│       ├── resolvers.txt        # Public DNS resolvers
│       ├── subdomains.txt       # (downloaded by install.sh)
│       └── README.md            # Wordlist download instructions
├── targets/                     # (create per-host notes as you test)
└── reports/                     # (store report drafts here)
```

---

## Quick Start

### 1. Install tools

```bash
cd recon
chmod +x install.sh
./install.sh
```

This installs all required tools (Go-based, Python, binaries) and downloads wordlists. Requires:
- **Go 1.21+**
- **Python 3.8+**
- `curl`, `git`, `jq`

### 2. (Optional) Set API keys for better coverage

```bash
# GitHub token — enables github-subdomains (finds subs leaked in code)
export GITHUB_TOKEN=ghp_your_token_here

# ProjectDiscovery Cloud Platform — enables chaos dataset
export PDCP_API_KEY=your_key_here
```

### 3. Run the full recon pipeline

```bash
chmod +x tesla_recon.sh
./tesla_recon.sh
```

This runs all 5 phases sequentially. Output is saved to `recon/output/<timestamp>/`.

### 4. Or run individual phases

```bash
./tesla_recon.sh --phase enum       # Phase 1: Subdomain enumeration
./tesla_recon.sh --phase resolve    # Phase 2: DNS resolution + takeover check
./tesla_recon.sh --phase probe      # Phase 3: HTTP probing (live hosts)
./tesla_recon.sh --phase finger     # Phase 4: Tech fingerprinting + JS analysis
./tesla_recon.sh --phase triage     # Phase 5: Categorize & prioritize
```

### 5. Deep-dive on a specific target

Once triage identifies high-value hosts (apps with auth, APIs), run endpoint discovery:

```bash
chmod +x endpoint_discovery.sh
./endpoint_discovery.sh https://some-interesting-app.tesla.com
```

---

## Pipeline Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         RECON PIPELINE                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Phase 1: ENUMERATE                                                 │
│  ┌─────────────┐ ┌──────────┐ ┌─────────────┐ ┌────────┐         │
│  │  subfinder   │ │  amass   │ │ assetfinder │ │ crt.sh │  ...    │
│  └──────┬──────┘ └────┬─────┘ └──────┬──────┘ └───┬────┘         │
│         └──────────────┴──────────────┴────────────┘               │
│                         │                                           │
│                         ▼                                           │
│              all_subdomains.txt (deduplicated, OOS filtered)        │
│                         │                                           │
│  Phase 2: RESOLVE       ▼                                           │
│  ┌──────────────────────────────────────┐                          │
│  │  dnsx — A/AAAA/CNAME records         │                          │
│  │  + dangling CNAME detection          │                          │
│  └──────────────────┬───────────────────┘                          │
│                     │                                               │
│  Phase 3: PROBE     ▼                                               │
│  ┌──────────────────────────────────────┐                          │
│  │  httpx — status, title, tech, length │                          │
│  └──────────────────┬───────────────────┘                          │
│                     │                                               │
│  Phase 4: FINGERPRINT  ▼                                            │
│  ┌──────────────────────────────────────┐                          │
│  │  nuclei tech-detect                  │                          │
│  │  JS file extraction + secret grep    │                          │
│  │  API endpoint extraction             │                          │
│  └──────────────────┬───────────────────┘                          │
│                     │                                               │
│  Phase 5: TRIAGE    ▼                                               │
│  ┌──────────────────────────────────────┐                          │
│  │  Categorize into:                    │                          │
│  │    • Apps with auth (HIGH VALUE)     │                          │
│  │    • API endpoints                   │                          │
│  │    • Static/marketing (low value)    │                          │
│  │    • Redirects / errors              │                          │
│  └──────────────────────────────────────┘                          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## What to Do with Results

After the pipeline runs, check these files in order:

| Priority | File | Action |
|---|---|---|
| 1 | `triage/apps_with_auth.txt` | These have login/dashboards — test for IDOR, BAC, ATO |
| 2 | `triage/api_hosts.txt` | API endpoints — test authz, injection, logic |
| 3 | `fingerprinted/potential_secrets.txt` | Leaked keys/tokens in JS — verify & report |
| 4 | `fingerprinted/api_endpoints.txt` | Hidden API paths — fuzz with your own auth |
| 5 | `resolved/takeover_candidates.txt` | Dangling CNAMEs — verify takeover is possible |
| 6 | `triage/server_errors.txt` | 5xx responses — might indicate misconfigs |

---

## Testing Methodology (Post-Recon)

Once you have high-value targets identified:

### IDOR / Broken Access Control
1. Create **two of your own accounts** (Account A, Account B)
2. Perform actions as Account A, capture object IDs (order IDs, user IDs, etc.)
3. Replay the request as Account B — does it work? That's IDOR.
4. Check both **read** (GET) and **write** (PUT/POST/DELETE) operations.

### SSRF
1. Look for any "fetch URL", "import", "webhook", "PDF export", "image from URL" features
2. Test with Burp Collaborator / interact.sh to confirm out-of-band callbacks
3. Try `http://169.254.169.254/latest/meta-data/` for cloud metadata access

### Auth Logic / Account Takeover
1. Test password reset flows (token predictability, token reuse, no rate limit)
2. Check OAuth flows for redirect_uri manipulation
3. Test session handling (fixation, token leakage in URLs/referrer)

### SQL Injection
1. Focus on search, filter, sort parameters
2. Try in unexpected places: headers, cookies, JSON body values
3. Use time-based blind techniques against WAF-protected targets

---

## Rules of Engagement — Reminders

- **Own accounts only.** Never touch another user's data.
- **Stop & report within 24h** if you discover access to someone else's data.
- **No DoS / brute force** without written approval.
- **No form spam** — be surgical, not noisy.
- **Register with** `username@bugcrowdninja.com`.
- **Delete any inadvertently accessed data** and prove deletion.

See `scope.md` for the full in-scope/out-of-scope reference.

---

## Options & Flags

```
tesla_recon.sh options:
  --phase <name>    Run a specific phase: enum, resolve, probe, finger, triage
  --threads <N>     Thread count (default: 50)
  --output <DIR>    Custom output directory
  -h, --help        Show help

endpoint_discovery.sh:
  Usage: ./endpoint_discovery.sh <target_url>
```

---

## Contributing

This is a private research repo. Add your findings, custom wordlists, and target notes as you discover them. Keep sensitive data (tokens, credentials, PII) **out of git** — use `.gitignore`.

---

## Disclaimer

This toolkit is for **authorized security research only** under Tesla's public bug bounty program. Unauthorized access to computer systems is illegal. Always follow the program's Rules of Engagement and applicable laws.
