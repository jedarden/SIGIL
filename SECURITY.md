# 🔒 Security Policy

> Responsible disclosure guidelines for security vulnerabilities in SIGIL.

---

## 🚨 Reporting a Vulnerability

**Do NOT file public issues for security vulnerabilities.**

Public disclosure of security vulnerabilities puts all SIGIL users at risk. Instead, follow our responsible disclosure process.

---

## 📧 How to Report

### Option 1: Email (Encrypted Preferred)

Send your report to: **security@sigil.sh**

**PGP Key**:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Sigil Security v1.0

[Full PGP key would be here in production]

-----END PGP PUBLIC KEY BLOCK-----
```

> 💡 **Tip**: Encrypt sensitive reports with our PGP key to protect vulnerability details during transmission.

### Option 2: GitHub Security Advisory

1. Go to [GitHub Security Advisory](https://github.com/jedarden/sigil/security/advisories)
2. Click "Report a vulnerability"
3. Fill in the form with details
4. GitHub will privately share the report with maintainers

---

## 📋 What to Include

Your report should include:

1. **Description**: What is the vulnerability?
2. **Impact**: What is the security impact?
3. **Reproduction**: Steps to reproduce the issue
4. **Proof of Concept**: Code or commands demonstrating the vulnerability
5. **Suggested Fix**: (Optional) How you think it should be fixed
6. **Affected Versions**: Which versions are affected?

---

## ⏱️ Response Timeline

| Stage | Timeline |
|-------|----------|
| **Receipt** | Within 48 hours |
| **Initial Assessment** | Within 7 days |
| **Detailed Analysis** | Within 14 days |
| **Fix Development** | Based on severity |
| **Public Disclosure** | After fix is released |

---

## 🎯 Severity Assessment

We classify vulnerabilities using CVSS v3.1:

| Severity | CVSS Score | Response Time |
|----------|------------|---------------|
| **Critical** | 9.0-10.0 | Immediate (within 48 hours) |
| **High** | 7.0-8.9 | Within 7 days |
| **Medium** | 4.0-6.9 | Within 30 days |
| **Low** | 0.1-3.9 | Next release |

---

## 🔄 Disclosure Process

1. **Receipt**: We acknowledge your report within 48 hours
2. **Validation**: We reproduce and validate the vulnerability
3. **Fix Development**: We develop a fix (timeline depends on severity)
4. **Coordination**: We coordinate release with you
5. **Public Disclosure**: We publish the advisory after the fix is released

### Coordinated Release

- We'll work with you to set a disclosure date
- You'll be credited in the advisory (unless you prefer to remain anonymous)
- We'll publish the advisory after the fix is available

---

## 🛡️ Safe Harbor

SIGIL commits to:

- **No legal action** against researchers who follow this policy
- **Credit** for valid vulnerability reports
- **Communication** throughout the disclosure process
- **Protection** of your identity (if requested)

---

## ⚠️ What NOT to Do

- ❌ **Don't** file public issues for security vulnerabilities
- ❌ **Don't** disclose vulnerabilities publicly before coordination
- ❌ **Don't** exploit vulnerabilities for any purpose other than testing
- ❌ **Don't** access or modify user data without permission

---

## 🔍 Bug Bounty

SIGIL does not currently offer a bug bounty program. However, we recognize valuable security research through:

- **Credits** in security advisories
- **Acknowledgments** in release notes
- **Invitations** to contribute to security improvements

---

## 📞 Contact

For general security questions (not vulnerability reports):

- **Email**: security@sigil.sh
- **Discussions**: [GitHub Security Discussions](https://github.com/jedarden/sigil/discussions/categories/security)

> ⚠️ **Warning**: For vulnerability reports, use the private reporting methods above. Do not use public discussions.

---

## 📚 Related Resources

- [Contributing Guide](CONTRIBUTING.md) — Development practices
- [Security Best Practices](docs/concepts.md#threat-model) — How SIGIL protects secrets
- [Audit Log](#audit-log) — SIGIL's internal security logging

---

## 🔐 Audit Log

SIGIL maintains an audit log of all secret access attempts. This log is:

- **Append-only**: Cannot be modified or deleted
- **Encrypted**: Protected at rest
- **Tamper-evident**: Hash chain ensures integrity
- **Monitored**: Alerts on suspicious activity

> 💡 **Tip**: Regular review of the audit log (`~/.sigil/vault/audit.jsonl`) is recommended for security-sensitive deployments.

---

## 👉 Thank You

Security researchers help make SIGIL safer for everyone. We appreciate your responsible disclosure!
