# Changelog

All notable changes to Apiary are documented here. The project uses semantic
versioning beginning with the public beta series.

## [Unreleased]

### Added

- NIP-98 protected remote cockpit with scoped host and per-agent management.
- Explicit, CSRF-protected browser-session logout and server-side revocation.
- Governed MCP and AG-UI access tokens with per-agent authorization.
- macOS `.app` and DMG packaging with Developer ID signing, notarization gates,
  and SHA-256 release checksums.

### Security

- Private cockpit assets and every control-plane response are marked
  `Cache-Control: no-store`.
- Unauthenticated visitors receive a minimal sign-in document rather than the
  cockpit application shell.

### Known limitations

- Independent security review has not yet been completed.
- NIP-46 remote-signer custody and compromised-key rotation are not complete.
- Production DMGs require Apple notarization credentials and a clean-machine
  installation check before tagging a release.
