# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in cpmesh, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities by emailing the maintainers or using GitHub's private vulnerability reporting.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- We will acknowledge your report within 48 hours
- We will provide an initial assessment within 7 days
- We will work with you to understand and resolve the issue

## Security Considerations

cpmesh handles encrypted clipboard data. The server is designed as a relay that only sees ciphertext. If you find any scenario where plaintext clipboard data could be exposed to the server or other unauthorized parties, this is a critical security issue and should be reported immediately.

The relay is also not trusted with integrity: clipboard entries are bound to their context and signed by the sending device, group keys are wrapped only to identity-certified encryption keys, and pairing uses a committed short authentication string. Any way for the relay (or anyone without a member device's private keys) to make a device accept a relabelled, spliced, re-attributed or replayed entry, to learn a group key, or to pass pairing with a substituted key, is a security issue.

Accounts are protected by two-factor authentication, and the admin console needs a session confirmed with it. Any way to sign in, or to act in the admin console, without the account's second factor (or beyond the permissions of a role) is a security issue too.
