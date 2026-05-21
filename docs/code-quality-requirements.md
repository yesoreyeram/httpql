# Code Quality Requirements

## CQR-01 Build and Test Health
- Code shall compile using `go build ./...`.
- Test suite shall pass using `go test ./... -race`.

## CQR-02 Minimal and Focused Changes
- Changes shall be scoped to the requirement being implemented.
- Unrelated refactors shall be avoided unless required for correctness/safety.

## CQR-03 Readability
- Naming shall be clear and consistent with surrounding package conventions.
- Complex behavior shall be decomposed into testable functions.

## CQR-04 Error Quality
- Errors shall preserve useful context (operation, field, or request alias).
- Public-facing errors shall be actionable.

## CQR-05 Test Coverage Expectations
- New behavior shall include unit or integration tests in corresponding package.
- Security-sensitive behavior shall include explicit negative tests.

## CQR-06 API Stability
- Public package changes shall be deliberate and documented.

