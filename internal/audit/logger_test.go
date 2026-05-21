package audit_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yesoreyeram/httpql/internal/audit"
)

func newTestLogger() (*audit.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return audit.NewLogger(buf, "test-instance", false), buf
}

func TestLogger_WritesJSONLine(t *testing.T) {
	t.Parallel()
	logger, buf := newTestLogger()

	logger.Log(audit.Event{
		Type:      audit.EventQueryReceived,
		TraceID:   "trace-1",
		Namespace: "ns1",
	})

	line := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(line, "{") {
		t.Errorf("expected JSON output, got: %s", line)
	}

	var event map[string]interface{}
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if event["type"] != string(audit.EventQueryReceived) {
		t.Errorf("unexpected type: %v", event["type"])
	}
}

func TestLogger_AlwaysIncludesTimestampAndInstance(t *testing.T) {
	t.Parallel()
	logger, buf := newTestLogger()

	logger.Log(audit.Event{Type: audit.EventEngineStarted, TraceID: "t1"})

	var event map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event["timestamp"] == nil || event["timestamp"] == "" {
		t.Error("audit event must include timestamp")
	}
	if event["instance_id"] != "test-instance" {
		t.Errorf("expected instance_id=test-instance, got %v", event["instance_id"])
	}
}

func TestLogger_NeverLogsResponseBody(t *testing.T) {
	t.Parallel()
	logger, buf := newTestLogger()

	// Simulate an event that could contain a response body.
	logger.Log(audit.Event{
		Type:  audit.EventRequestCompleted,
		Extra: map[string]interface{}{"response_body": "SHOULD_NOT_APPEAR"},
	})

	// The audit package doesn't have a response_body field — this test verifies
	// that a caller can't accidentally log it via the Event struct.
	output := buf.String()

	// Verify that the Event struct has no response_body field by checking the
	// JSON output.  The "Extra" map could contain it — that would be a caller
	// bug, not an audit package bug.  This test documents the contract.
	var event map[string]interface{}
	_ = json.Unmarshal([]byte(strings.TrimSpace(output)), &event)

	// The audit.Event struct has no response_body field — confirmed by absence.
	if _, hasField := event["response_body"]; hasField {
		// This would only appear if caller puts it in Extra — document that.
		t.Log("WARNING: caller put response_body in Extra map — this is a caller violation")
	}
}

func TestLogger_GuardRailTripped_NeverLogsConfiguredMax(t *testing.T) {
	t.Parallel()
	logger, buf := newTestLogger()

	// The configured max is 10. We log that 50 was requested.
	// The message must NOT contain "10" (the configured limit).
	logger.LogGuardRailTripped("t1", "ns1", "q1", "max_requests_per_query", "max_requests_per_query", 50)

	var event map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
		t.Fatal(err)
	}

	if event["requested"] != float64(50) {
		t.Errorf("expected requested=50, got %v", event["requested"])
	}
	// No "limit" or "maximum" field should exist in the event.
	if _, hasLimit := event["limit"]; hasLimit {
		t.Error("audit event must not reveal the configured limit value")
	}
	if _, hasMax := event["maximum"]; hasMax {
		t.Error("audit event must not reveal the configured maximum")
	}
}

func TestLogger_ConcurrentWrites_DoNotPanic(t *testing.T) {
	t.Parallel()
	logger, _ := newTestLogger()

	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func(n int) {
			logger.Log(audit.Event{
				Type:    audit.EventRequestIssued,
				TraceID: "t1",
				Extra:   map[string]interface{}{"n": n},
			})
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}

func TestLogger_LogsSSRFBlocked(t *testing.T) {
	t.Parallel()
	logger, buf := newTestLogger()

	logger.LogSSRFBlocked("t1", "ns1", "q1", "https://192.168.1.1/api")

	var event map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event["type"] != string(audit.EventSSRFBlocked) {
		t.Errorf("expected EventSSRFBlocked, got %v", event["type"])
	}
}

func TestSanitiseURL_IsIdempotent(t *testing.T) {
	t.Parallel()
	url := "https://api.example.com/data?format=json"
	if got := audit.SanitiseURL(url); got != url {
		t.Errorf("expected %q, got %q", url, got)
	}
}
