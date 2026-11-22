# 🛡️ authz-probe Security Assessment Report

**Target:** `http://localhost:5000`
**Total Findings:** 6

| Severity | Type | Endpoint | Tested Identity | Status |
|:---:|:---|:---|:---:|:---:|
| 🔴 HIGH | BFLA (API5:2023) | `GET /users/v1/_debug` | `user_a` | `200` |
| 🔴 HIGH | BFLA (API5:2023) | `GET /users/v1/_debug` | `user_b` | `200` |
| 🔴 HIGH | Missing Authentication (API2:2023) | `GET /users/v1/_debug` | `anonymous` | `200` |
| 🔴 HIGH | BOLA / IDOR (API1:2023) | `GET /users/v1/alice` | `user_b` | `200` |
| 🔴 HIGH | BOLA / IDOR (API1:2023) | `GET /users/v1/alice` | `admin` | `200` |
| 🔴 HIGH | Missing Authentication (API2:2023) | `GET /users/v1/alice` | `anonymous` | `200` |

## Detailed Findings & Remediation

### 1. BFLA (API5:2023) on `/users/v1/_debug`
- **Severity:** `HIGH`
- **Tested Identity:** `user_a`
- **HTTP Response:** `200`
- **Evidence:** Administrative endpoint accessible by regular identity 'user_a'
- **💡 Remediation:** Implement role-based access control (RBAC): verify caller has 'admin' role before executing.

### 2. BFLA (API5:2023) on `/users/v1/_debug`
- **Severity:** `HIGH`
- **Tested Identity:** `user_b`
- **HTTP Response:** `200`
- **Evidence:** Administrative endpoint accessible by regular identity 'user_b'
- **💡 Remediation:** Implement role-based access control (RBAC): verify caller has 'admin' role before executing.

### 3. Missing Authentication (API2:2023) on `/users/v1/_debug`
- **Severity:** `HIGH`
- **Tested Identity:** `anonymous`
- **HTTP Response:** `200`
- **Evidence:** Endpoint accessible without authentication (HTTP 200)
- **💡 Remediation:** Enforce authentication middleware or decorator (e.g., @login_required) on this route.

### 4. BOLA / IDOR (API1:2023) on `/users/v1/alice`
- **Severity:** `HIGH`
- **Tested Identity:** `user_b`
- **HTTP Response:** `200`
- **Evidence:** HTTP 200 leaked data of 'alice' to unauthorized 'user_b'
- **💡 Remediation:** Validate object ownership on every request: verify current_user.id == object.owner_id.

### 5. BOLA / IDOR (API1:2023) on `/users/v1/alice`
- **Severity:** `HIGH`
- **Tested Identity:** `admin`
- **HTTP Response:** `200`
- **Evidence:** HTTP 200 leaked data of 'alice' to unauthorized 'admin'
- **💡 Remediation:** Validate object ownership on every request: verify current_user.id == object.owner_id.

### 6. Missing Authentication (API2:2023) on `/users/v1/alice`
- **Severity:** `HIGH`
- **Tested Identity:** `anonymous`
- **HTTP Response:** `200`
- **Evidence:** Endpoint accessible without authentication (HTTP 200)
- **💡 Remediation:** Enforce authentication middleware or decorator (e.g., @login_required) on this route.
