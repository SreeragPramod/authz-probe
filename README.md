# authz-probe

> Spec-driven API authorization tester — detects BOLA/IDOR, BFLA, and missing authentication.

🚧 **Work in progress** — MVP coming soon.

## How authz-probe Compares to Existing Tools

| Capability | Burp Autorize | Burp AuthMatrix | OWASP ZAP | Schemathesis | **authz-probe** |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Spec-Driven (OpenAPI)** | ❌ No | ❌ No | ⚠️ Partial | ✅ Yes | **✅ Yes** |
| **Headless CI/CD Native** | ❌ No (GUI Proxy) | ❌ No (GUI Proxy) | ✅ Yes | ✅ Yes | **✅ Yes (44s CI run)** |
| **Multi-Identity BOLA Matrix** | ✅ Yes | ✅ Yes | ❌ No | ❌ No | **✅ Yes** |
| **Native SARIF Output** | ❌ No | ❌ No | ⚠️ Plugin | ❌ No | **✅ Yes (OASIS 2.1.0)** |
| **Requires Manual Browsing**| Yes (Proxy driven) | Yes (Manual grid) | No | No | **No (Fully automated)** |

### Key Architectural Differences
- **Unlike Burp Autorize:** Autorize is an interactive proxy extension for human penetration testers clicking through a UI. `authz-probe` is a developer-friendly, headless CLI tool built for automated CI/CD pipelines.
- **Unlike OWASP ZAP:** Traditional DAST scanners scan with a single session and flag status code anomalies. They cannot detect BOLA because `200 OK` appears normal. `authz-probe` models cross-identity object ownership.
- **Unlike Schemathesis:** Schemathesis fuzzes inputs to trigger `500 Internal Server Errors` and schema violations. `authz-probe` tests the authorization boundary between different valid users.
