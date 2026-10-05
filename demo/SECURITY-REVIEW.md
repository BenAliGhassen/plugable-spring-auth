# Security Review

Review scope: authentication, JWT and refresh-token handling, token rotation/reuse detection, cookies, validation, persistence, and exception handling.

## Finding

### High — Logout does not clear cookies when refresh-token revocation fails

**Location:** `src/main/java/com/example/demo/User/UserController.java`, logout handler around lines 75–84; `src/main/java/com/example/demo/RefreshToken/RefreshService.java`, `revoke`; `src/main/java/com/example/demo/GlobalExceptionHandler.java`, `InvalidToken` handler.

The logout handler revokes the supplied refresh token before constructing its cookie-clearing response. If the token is invalid or already revoked, `RefreshService.revoke` throws `InvalidToken`, which the global handler maps to `401 Unauthorized`. The controller therefore never sends the expired access and refresh cookies, leaving stale cookies in the browser and making logout behavior inconsistent.

**Remediation:** Make logout idempotent: always send both expired cookies, even when refresh-token revocation fails because the token is already invalid or revoked. Alternatively, make refresh-token revocation a no-op for a missing or previously revoked token when called by logout.

## Previously Reported Findings

- The refresh cookie path was changed to `/auth`, which covers `/auth/refresh` and `/auth/logout`.
- Concurrent refresh-token reuse is now guarded by a conditional atomic consume; reuse detection revokes the associated token family.
