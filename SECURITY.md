# Security Policy

## Supported Versions

Security fixes target the latest release.

## Reporting

Do not open a public issue containing session content, filesystem paths, credentials, tokens, personal information, or unredacted diagnostic output.

Report vulnerabilities through GitHub private vulnerability reporting for `T50-Systems/pi-error-aggregator`.

Include the affected version, platform, impact, and a minimal redacted reproduction.

## Security Boundary

The extension reads session files available to the Pi process user. It is not a filesystem sandbox. It narrows output through explicit error extraction, redaction, control sanitization, one-way origin identifiers, and mandatory resource/output limits. It does not persist derived diagnostics or use the network.
