# [Vulnerability Title] — [In-scope Asset]

> Submit via YesWeHack. Use your YWH alias. No public disclosure.

## Summary
A clear, one-paragraph description of the vulnerability, where it is, and why it matters to BookBeat and its users.

## Affected Asset
- **URL / Endpoint:** `https://api.bookbeat.com/...`
- **Vulnerability type:** (IDOR / BAC / SQLi / SSRF / Business Logic / ...)
- **Authentication required:** (Yes/No — and what privilege level)

## Severity
- **CVSS 3.1 Vector:** `CVSS:3.1/AV:.../AC:.../...`
- **Score:** X.X (Low/Medium/High/Critical)
- **Business impact:** What can an attacker actually achieve? (e.g., read any user's library/payment info, access premium content without paying)

## Steps to Reproduce
1. Authenticate as Account A (`POST /api/login`, headers `bb-client: BookBeatApp`, `bb-device: api ywh`, UA contains ` yeswehack `).
2. ...
3. ...

Include exact requests/responses (sanitized), payloads, and commands.

```http
GET /api/... HTTP/1.1
Host: api.bookbeat.com
User-Agent: ... yeswehack
Authorization: Bearer <accountB_token>
bb-client: BookBeatApp
bb-device: api ywh
```

## Proof of Concept
- Screenshots/video showing the exploit and the final impact.
- For IDOR: show Account B accessing Account A's resource — **with only your own two accounts**.

## Impact
Concrete description of what an attacker gains and the risk to users/BookBeat.

## Remediation
Specific, actionable fix advice (e.g., enforce object-level authorization checks server-side; validate that the requested resource belongs to the authenticated user).

## Notes
- Did NOT access, copy, or modify any third-party user data.
- All testing performed with the ` yeswehack ` User-Agent and own accounts.
