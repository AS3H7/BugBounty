# BookBeat — Testing Methodology

A subscription audiobook/eBook service with a narrow, API-heavy scope. The
high-value bugs live in **object-level authorization (IDOR)** and **business
logic around subscriptions/content access**. This guide is organized by where
the money is.

> Every active request must carry the ` yeswehack ` User-Agent, be rate-limited
> (manual / surgical — no scanners), and target only in-scope hosts. Use
> `bb-request.sh` which enforces all three.

---

## 0. Setup
1. Self-register at bookbeat.com using your **YesWeHack email alias**.
2. Create a **second** account (for IDOR/BAC) using another alias.
3. Authenticate both via the API:
   ```bash
   export BB_USERNAME=A@alias  BB_PASSWORD=...; BB_TOKEN_FILE=/tmp/.bb_A ./api_login.sh
   export BB_USERNAME=B@alias  BB_PASSWORD=...; BB_TOKEN_FILE=/tmp/.bb_B ./api_login.sh
   ```
4. Configure your proxy (Burp/Caido) to append ` yeswehack ` to the User-Agent on ALL traffic — set a match/replace rule so you never forget.

---

## 1. IDOR / Broken Access Control  *(highest value)*
The classic for a multi-user content service.

- Map every endpoint that returns **user-owned data**: library/saved books, bookmarks, reading progress, profile, payment/subscription, downloads, family/child profiles.
- For each, capture an object ID as Account A, then replay as Account B and unauthenticated.
- Test **all verbs**: GET (read), PUT/PATCH (modify), DELETE (destroy).
- Watch for IDs in: path segments, query params, JSON body, and headers.
- Try ID formats: sequential ints, UUIDs (sometimes leaked elsewhere), base64-wrapped IDs.
- Use `idor_check.sh` to confirm safely. **If B reads A's data → stop, minimal proof, report.**

## 2. Business Logic *(high value, hard to dupe)*
A subscription service has rich logic to abuse:

- **Premium/paid content access** without an active subscription — can a free/trial/expired account stream or download a paid title? Check the download/stream token issuance endpoint directly.
- **Trial abuse** that yields real value (not just "make many trials" — that's rate-limiting/abuse, likely OOS). Focus on *entitlement* flaws.
- **Subscription tier confusion** — does changing a plan ID / region grant more than paid for?
- **Family/multi-profile** seat limits — can you exceed seats or attach to another household?
- **Price/quantity tampering** in any purchase/upgrade flow.
- **Race conditions** on redeem/coupon/gift flows (be gentle — no flooding).

## 3. Authentication / Privilege Escalation
- Inspect the login/token flow (`/api/login`). How are tokens scoped? Any role/claim in a JWT you can tamper (alg=none, weak secret, role field)?
- Horizontal: Account B acting as A (covered in IDOR).
- Vertical: any user→admin/staff endpoints reachable with a normal token?
- Token reuse across the three APIs (api / search-api / edge) — does a token meant for one work on another with more privilege?

## 4. Injection — focus search-api
- `search-api.bookbeat.com` is the obvious injection surface (search/filter/sort params).
- Test for SQLi (error-based, boolean, time-based) **manually and gently**.
- Test reflected/stored XSS where output is rendered to *other* users (self-XSS is OOS).

## 5. SSRF / LFI / RFI / XXE / XSPA
- Hunt any feature that fetches a URL, imports, parses XML, or processes uploads (cover art, OPDS/feed imports, webhooks).
- **Blind SSRF without PoC is OUT of scope** — you must demonstrate real impact (internal resource read, metadata, etc.).

## 6. CORS / CSRF / Open Redirect *(must show real impact)*
- CORS: look for reflected `Origin` + `Access-Control-Allow-Credentials: true` on an endpoint returning sensitive data → demonstrate cross-origin theft.
- CSRF: only state-changing, integrity-affecting actions count (login/logout/cart are OOS).
- Open redirect: in scope, but header-based/unexploitable variants are OOS.

## 7. Exposed Secrets
- Review web/app JS bundles and API responses for secrets on **in-scope assets** that affect scope. (Public Firebase/Maps keys are explicitly OOS.)

---

## Quick "is it worth reporting?" filter
Before writing a report, check it's NOT on the non-qualifying list (rate-limiting,
user enumeration, GraphQL introspection, self-XSS, blind SSRF w/o PoC, session
mgmt, missing headers, SPF/DKIM, public API keys, etc.). If it needs MITM or
physical access, it's out. **Impact + PoC or it doesn't count.**
