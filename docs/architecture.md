# Architecture & Design Document: authz-probe

## 1. Overview
authz-probe is an automated, spec-driven API authorization testing engine designed to systematically identify Broken Object Level Authorization (BOLA/IDOR), Broken Function Level Authorization (BFLA), and Missing Authentication in REST APIs.

## 2. Core Modules
- `spec.py`: Parses OpenAPI v3 specifications to extract path templates, methods, parameters, and schemas.
- `policy.py`: Loads identity definitions, authentication headers (from env), and role-based access rules.
- `seeder.py`: Executes authenticated resource creation requests to establish verifiable object ownership per identity.
- `engine.py`: Performs cross-identity request replay using matrix permutation (Identity A's token -> Identity B's object).
- `verdict.py`: Evaluates status codes, headers, and body reflection markers to classify findings as VULNERABLE, SUSPICIOUS, or OK.
- `reporters/`: Formats output into interactive CLI tables (Rich), JSON, Markdown, and SARIF for GitHub Security.

## 3. Verdict Decision Table
- 401/403: OK (Explicit rejection)
- 404: OK (Secure resource masking)
- 200/20x with owner data reflection: VULNERABLE (BOLA/BFLA confirmed)
- 200/20x with generic/empty body: SUSPICIOUS (Potential false-positive; manual review needed)

## 4. Safety & False Positive Mitigations
- Read-only safe mode enabled by default (destructive verbs skipped unless explicitly overridden).
- Domain allowlisting to prevent out-of-scope testing.
- Rate limiting to protect target availability.

## 5. Visual Pipeline Workflow

```mermaid
flowchart TD
    Spec[OpenAPI Spec] --> Parser[Spec Parser]
    Policy[Policy File] --> Loader[Policy Loader]
    Parser --> Seeder[Seeder Stage]
    Loader --> Seeder
    Seeder --> Engine[Cross-Identity Replay Engine]
    Engine -->|Replay Matrix| Target[Target API]
    Target -->|Status Code + Body| Verdict[Verdict Engine]
    Verdict --> Output[Rich Console & SARIF Reports]
