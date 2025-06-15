
## 🛡️ 𝗨𝗟𝗧𝗜𝗠𝗔𝗧𝗘 𝗩𝗨𝗟𝗡𝗘𝗥𝗔𝗕𝗜𝗟𝗜𝗧𝗬 𝗖𝗛𝗘𝗖𝗞𝗟𝗜𝗦𝗧 𝗙𝗢𝗥 𝗖𝗢𝗗𝗘 𝗥𝗘𝗩𝗜𝗘𝗪

---

### 🔢 1–20: Input Injection Vulnerabilities

* [ ] SQL Injection (classic, blind, time-based)
* [ ] Command Injection (`os.system`, `exec`, etc.)
* [ ] XSS – Reflected
* [ ] XSS – Stored
* [ ] XSS – DOM-based
* [ ] HTML Injection
* [ ] JSON Injection
* [ ] XML Injection (XXE)
* [ ] XPath Injection
* [ ] LDAP Injection
* [ ] Regex Injection
* [ ] Host Header Injection
* [ ] Response Splitting
* [ ] CRLF Injection
* [ ] Header Injection
* [ ] Log Injection
* [ ] Format String Injection
* [ ] Template Injection (e.g., Jinja2, EJS)
* [ ] Shell Expansion (`subprocess`, backticks)
* [ ] Prototype Pollution (JS)

---

### 🔐 21–40: Authentication & Authorization

* [ ] Hardcoded credentials
* [ ] Weak/default credentials
* [ ] Plaintext password storage
* [ ] No rate limiting (brute force)
* [ ] Insecure password reset (tokens, links)
* [ ] Broken session management
* [ ] Session fixation
* [ ] No logout / session expiry
* [ ] Token leakage via URL or referrer
* [ ] Missing MFA or 2FA
* [ ] IDOR (Insecure Direct Object Reference)
* [ ] Missing auth checks on sensitive APIs
* [ ] Horizontal privilege escalation
* [ ] Vertical privilege escalation
* [ ] Bypassable RBAC/ABAC
* [ ] Insecure “remember me” token
* [ ] Replay attack vulnerable
* [ ] JWT: weak secret, none alg, no expiry
* [ ] Open redirect on login flows
* [ ] Token reuse across devices

---

### 🧬 41–60: Input Validation & Encoding

* [ ] Missing type checks / input constraints
* [ ] Lack of length checks (DoS)
* [ ] Accepting unexpected formats (e.g., YAML, XML)
* [ ] Trusting client-side validation only
* [ ] No encoding/escaping for user input
* [ ] Unsafe HTML rendering (e.g., `innerHTML`)
* [ ] Unsafe markdown rendering
* [ ] Accepting serialized objects (pickle, etc.)
* [ ] Unsafe deserialization (Java, PHP, Python)
* [ ] Magic number abuse / hidden field tampering
* [ ] Mass assignment in objects
* [ ] Type confusion / coercion issues
* [ ] Unsafe object instantiation (e.g., `eval`)
* [ ] JSON parsing w/o validation (`eval`, `Function`)
* [ ] Accepting base64 or hex without limits
* [ ] Use of dangerous MIME types
* [ ] Multipart parsing errors
* [ ] Weak input filters (blacklist over whitelist)
* [ ] Nested input structures without depth check
* [ ] Missing canonicalization of input paths

---

### 🧾 61–80: File, Path & Upload Vulnerabilities

* [ ] Path Traversal (`../`)
* [ ] Null byte injection in file names
* [ ] Unsafe file upload (no type check)
* [ ] Executable upload allowed
* [ ] File overwrite (no randomization or checks)
* [ ] Unsafe file reads (e.g., `/etc/passwd`)
* [ ] Insecure download endpoints (no ACL)
* [ ] Temporary file creation issues
* [ ] Local file inclusion (LFI)
* [ ] Remote file inclusion (RFI)
* [ ] Using user input as file path
* [ ] Symlink abuse
* [ ] Archive extraction (Zip Slip)
* [ ] File type spoofing (Content-Type mismatch)
* [ ] No antivirus/malware scan on upload
* [ ] Public file listing
* [ ] File metadata leakage
* [ ] No upload rate limiting
* [ ] File size DOS (upload bombing)
* [ ] Unauthenticated file access

---

### 🔐 81–100: Cryptography & Secrets

* [ ] Hardcoded encryption keys
* [ ] Weak crypto algorithm (MD5, SHA1, RC4)
* [ ] ECB mode used
* [ ] No key rotation
* [ ] Insecure random number generator
* [ ] No HMAC or integrity checks
* [ ] Static IV in encryption
* [ ] Encrypted data w/o expiry
* [ ] Exposed `.env` files
* [ ] Secrets in source control
* [ ] Secrets in client-side JS
* [ ] No TLS/SSL enforcement
* [ ] Downgrade attacks possible (no strict TLS config)
* [ ] JWT: no `exp`, `iat`, `aud`, etc.
* [ ] Use of `none` algorithm in JWT
* [ ] Insecure token storage (e.g., localStorage)
* [ ] Predictable token generation
* [ ] API keys reused across environments
* [ ] Shared secrets across services
* [ ] Missing encryption at rest

---

### ⚙️ 101–120: Configuration & Logic

* [ ] Debug mode enabled in production
* [ ] Verbose error messages
* [ ] Full stack trace disclosure
* [ ] Source code disclosure (`.git`, `.env`)
* [ ] Missing security headers (CSP, HSTS, etc.)
* [ ] CORS misconfigured (wildcard origins)
* [ ] Referrer leakage to 3rd parties
* [ ] No logging/audit trail
* [ ] Logging sensitive data (passwords, tokens)
* [ ] Time-based logic flaws (replay, race)
* [ ] Broken business logic (e.g., bypass price)
* [ ] Missing limits on loops/recursion
* [ ] Race conditions in transactions
* [ ] TOCTOU bugs (check then use)
* [ ] Infinite redirect loops
* [ ] Trusting client-side state (e.g., prices)
* [ ] Abuse of internal API endpoints
* [ ] Application-specific logic bypass
* [ ] Rate limiting bypass via IP rotation
* [ ] Insecure default config values

---

### 🛠️ 121–140: DevOps / Supply Chain / Cloud

* [ ] Secrets in CI/CD logs
* [ ] Insecure Dockerfile (e.g., root user)
* [ ] Exposed `.git` folder on server
* [ ] Dependency confusion / typosquatting
* [ ] Unpinned package versions
* [ ] Vulnerable third-party libraries
* [ ] Public S3 buckets or GCS
* [ ] Metadata service access (SSRF)
* [ ] Use of `curl | bash` in scripts
* [ ] `.npmrc`, `.pypirc` exposing tokens
* [ ] No dependency scanning (SCA tools)
* [ ] Build artifacts with secrets
* [ ] Exposed Grafana/Kibana dashboards
* [ ] Misconfigured firewall / open ports
* [ ] Helm chart secrets checked in
* [ ] Terraform state file leakage
* [ ] No infrastructure hardening
* [ ] Shell scripts with sudo without checks
* [ ] Unsafe AWS IAM policies
* [ ] No audit logging for deployments

