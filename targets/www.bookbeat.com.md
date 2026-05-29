# Target Analysis — www.bookbeat.com

> Source: passive recon (Wayback CDX archive only — no traffic sent to BookBeat).
> All active follow-up testing must use the ` yeswehack ` UA + your own accounts.

## Tech Stack
- **Next.js (App Router)** SPA — `_next/data/<buildId>/...`, `_next/static/chunks/app/(pages)/[market]/...`
- Multi-market: `se, fi, dk, de, nl, pl` (+ more). `market` / `resetMarket` params everywhere.
- Login at `/login` (and localized, e.g. `/fi/kirjaudu`).

## High-Interest Endpoints Discovered

### RPC-style account endpoints on the WEB origin (`/9h/<service>.<method>`)
These return account-scoped data and are the top IDOR / broken-auth / authz candidates:
- `GET /9h/accounts.devices`            -> registered devices (other users' devices?)
- `GET /9h/accounts.eligableForTrial`   -> trial eligibility (business-logic / trial abuse)
- `GET /9h/accounts.reactivate`         -> reactivation flow
- `GET /9h/accounts.settings`           -> account settings (PII?)
- `GET /9h/profiles.get`                -> profile data
- `GET /9h/users.subscription`          -> subscription/entitlement state

**Hypotheses to test (authenticated, 2 accounts):**
1. Do these take an account/user/profile ID param? If so -> replay Account A's ID as Account B (IDOR).
2. Is authorization enforced server-side, or just "logged in"? Try Account B's session against A's identifiers.
3. `accounts.eligableForTrial` / `users.subscription` -> can entitlement be flipped client-side or via tampered request (premium content without paying)?

### Login redirect (Open Redirect candidate — IN SCOPE)
- `/login.json?redirectTo=%2F%5Bmarket%5D%2Faccount%2Fsubscription&market=de`
- **Test:** Does `redirectTo` accept off-domain values (`//evil.com`, `https://evil.com`, `/\evil.com`, whitelisted-prefix bypasses like `https://www.bookbeat.com.evil.com`)? Need a real navigable redirect, not header-only.

### Subscription / account SPA routes
- `/[market]/account/cancel`
- `/[market]/account/manage-subscription`
- `/[market]/account/subscription`
- `/[market]/our-subscriptions`
- **Business logic:** cancel/manage/reactivate flows — can you manipulate plan IDs, price, or market to gain a cheaper/free tier, or extend trials?

## search-api.bookbeat.com — Injection surface
Endpoints: `/api/appsearch/books`, `/api/appsearch/suggest`, `/api/tabsearch`, `/api/tabsearch/books`
Parameters observed:
`query, kw, searchKey, author, authorId, narrator, narratorId, contributorId, format, language, lg, market, sortby, sortorder, limit, offset, page, includeErotic / includeerotic, kid / notonlykid, badgeid, series`

**Hypotheses:**
1. **SQLi / NoSQL / injection** on `query`, `kw`, `searchKey`, `author`, `sortby`, `sortorder` (sort params are classic injection points). Manual, gentle, time-based if blind.
2. **Content-filter bypass (business logic / access control):** `includeErotic`, `kid`, `notonlykid` control content visibility. Can a **kids profile** be made to return adult/erotic results by flipping these? Real impact = parental-control bypass.
3. **Reflected XSS** if any search param is echoed into a rendered response consumed by other users (self-XSS is OOS).

## Parameters of interest (full list)
`as_src, author, authorId, badgeid, coid, contributorId, evt, format, includeerotic, includeErotic, kid, kw, language, lg, limit, market, mid, narrator, narratorId, notonlykid, offset, other, p, page, pi, query, r, redirectTo, resetMarket, rn, sc, searchKey, Series, sh, sortby, sortorder, sw, ti, tl, v, Ver`

## Next Actions (you run these, YWH-tagged)
1. Capture the main Next.js JS bundle(s) -> give to me for static analysis (DOM-XSS sinks, the `/9h/` mechanism, client-side authz).
2. Authenticate 2 accounts (`api_login.sh`) and probe the `/9h/*` endpoints — note auth model + any ID params.
3. Test `redirectTo` for open redirect.
4. Probe search-api `sortby`/`sortorder`/`query` for injection, and `includeErotic`/`kid` for filter bypass.
