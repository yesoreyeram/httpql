// Package guardrails provides all enforcement mechanisms for the httpql engine
// guard rail system.  The sub-packages implement:
//
//   - Semaphore pools (hierarchical: global → namespace → per-query → per-origin)
//   - Rate limiters (token-bucket for bandwidth)
//   - Plan-time validation (static analysis before any network activity)
//   - Runtime context (tracks live resource usage and trips limits dynamically)
package guardrails
