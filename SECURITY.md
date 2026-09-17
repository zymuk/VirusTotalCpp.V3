# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.0 | Yes |
| < 1.0.0 | No |

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Report privately so
the fix ships before details are public:

- Use the GitHub private vulnerability reporting form (Security &gt; Report a
  vulnerability) on this repository.
- Or email the maintainers directly.

Include as much context as you can: the affected version, platform, a minimal
reproducer, and the impact you observed.

We aim to acknowledge reports within 5 business days and to keep you updated as
we work toward a fix.

## Secrets and API keys

- Never commit an API key, token, or any other secret to this repository.
- Always take keys from environment variables or a secret store at runtime.
- The test suite runs against a local mock HTTP server and does not contact the
  real VirusTotal API, so running tests never consumes quota or leaks keys.