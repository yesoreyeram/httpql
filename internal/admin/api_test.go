package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yesoreyeram/httpql/internal/admin"
	"github.com/yesoreyeram/httpql/internal/audit"
	"github.com/yesoreyeram/httpql/internal/cache"
	"github.com/yesoreyeram/httpql/internal/config"
	"github.com/yesoreyeram/httpql/internal/guardrails"
	"github.com/yesoreyeram/httpql/internal/policy"
)

func newTestAPI(t *testing.T, token string) (*admin.API, *http.ServeMux) {
	t.Helper()
	cfg := config.Default()
	resolver := policy.NewResolver(cfg)
	reqCache := cache.NewRequestCache(100, 1024*1024)
	respCache := cache.NewResponseCache(100, 1024*1024, 1000)
	semaPool := guardrails.NewSemaphorePool(guardrails.SemaphorePoolConfig{
		GlobalRequestsMax:        100,
		GlobalQueriesMax:         20,
		DefaultNSQueriesMax:      5,
		DefaultQueryRequestsMax:  5,
		DefaultOriginRequestsMax: 2,
	})
	logger := audit.NewLogger(&bytes.Buffer{}, "test", false)

	api, err := admin.NewAPI(cfg, resolver, reqCache, respCache, semaPool, logger, token)
	if err != nil {
		t.Fatalf("NewAPI failed: %v", err)
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	return api, mux
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

func TestAdminAPI_RequiresBearerToken(t *testing.T) {
	t.Parallel()
	_, mux := newTestAPI(t, "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAdminAPI_RejectsWrongToken(t *testing.T) {
	t.Parallel()
	_, mux := newTestAPI(t, "correct-token")

	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestAdminAPI_AcceptsCorrectToken(t *testing.T) {
	t.Parallel()
	_, mux := newTestAPI(t, "correct-token")

	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	req.Header.Set("Authorization", "Bearer correct-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAdminAPI_RejectsNonBearerScheme(t *testing.T) {
	t.Parallel()
	_, mux := newTestAPI(t, "correct-token")

	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	req.Header.Set("Authorization", "Basic correct-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-Bearer scheme, got %d", w.Code)
	}
}

// ─── /admin/health ────────────────────────────────────────────────────────────

func TestAdminAPI_Health_ReturnsStatusAndDigest(t *testing.T) {
	t.Parallel()
	_, mux := newTestAPI(t, "tok")

	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", body["status"])
	}
	if body["config_digest"] == "" || body["config_digest"] == nil {
		t.Error("health response must include config_digest")
	}
}

func TestAdminAPI_Health_RejectsPost(t *testing.T) {
	t.Parallel()
	_, mux := newTestAPI(t, "tok")

	req := httptest.NewRequest(http.MethodPost, "/admin/health", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ─── /admin/limits ────────────────────────────────────────────────────────────

func TestAdminAPI_Limits_ReturnsLimits(t *testing.T) {
	t.Parallel()
	_, mux := newTestAPI(t, "tok")

	req := httptest.NewRequest(http.MethodGet, "/admin/limits", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["limits"] == nil {
		t.Error("expected limits in response")
	}
}

func TestAdminAPI_Limits_NeverExposesSecretBackendCredentials(t *testing.T) {
	t.Parallel()
	_, mux := newTestAPI(t, "tok")

	req := httptest.NewRequest(http.MethodGet, "/admin/limits", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	body := w.Body.String()

	// These strings must never appear in the security section output.
	dangerousStrings := []string{"vault_token", "service_account_token_path", "aws_ssm"}
	for _, s := range dangerousStrings {
		if strings.Contains(strings.ToLower(body), s) {
			t.Errorf("admin API response must not contain sensitive config key %q", s)
		}
	}
}

// ─── /admin/cache/purge ───────────────────────────────────────────────────────

func TestAdminAPI_CachePurge_RequiresPost(t *testing.T) {
	t.Parallel()
	_, mux := newTestAPI(t, "tok")

	req := httptest.NewRequest(http.MethodGet, "/admin/cache/purge", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestAdminAPI_CachePurge_PurgesAll(t *testing.T) {
	t.Parallel()
	_, mux := newTestAPI(t, "tok")

	req := httptest.NewRequest(http.MethodPost, "/admin/cache/purge", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminAPI_CachePurge_PurgesNamespace(t *testing.T) {
	t.Parallel()
	_, mux := newTestAPI(t, "tok")

	req := httptest.NewRequest(http.MethodPost, "/admin/cache/purge?namespace=team-a&type=response", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != true {
		t.Error("expected ok=true")
	}
}

// ─── /admin/semaphores ────────────────────────────────────────────────────────

func TestAdminAPI_Semaphores_ReturnsAvailability(t *testing.T) {
	t.Parallel()
	_, mux := newTestAPI(t, "tok")

	req := httptest.NewRequest(http.MethodGet, "/admin/semaphores", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
