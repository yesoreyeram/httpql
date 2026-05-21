# CI/CD Requirements

## CI Requirements

### CI-01 Build Validation
- CI shall run `go build ./...` on pull requests and mainline branches.

### CI-02 Test Validation
- CI shall run `go test ./... -race` on pull requests and mainline branches.

### CI-03 Fast Failure
- CI shall fail pipeline on compile/test failures with clear logs.

### CI-04 Security Validation
- CI should include code scanning and dependency vulnerability checks.

### CI-05 Documentation Checks
- Documentation-only changes should still pass baseline CI checks.

## CD Requirements

### CD-01 Release Integrity
- Release artifacts shall be produced only from validated commits.

### CD-02 Traceability
- Releases shall map to immutable git commit SHAs and tags.

### CD-03 Rollback Readiness
- Deployment process shall support rollback to last known good version.

### CD-04 Change Visibility
- Release notes shall summarize functional/security changes and compatibility impacts.

## Governance
- Branch protection shall require successful CI checks before merge.
- Required checks should include build, tests, and security scanning.

