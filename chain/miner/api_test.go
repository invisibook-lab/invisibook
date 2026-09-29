package miner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// newTestAPI mounts the console over a service with a fake wallet.
func newTestAPI(t *testing.T, token string) http.Handler {
	t.Helper()
	gin.SetMode(gin.TestMode)
	svc, _, _ := newTestService(t, &fakeWallet{committed: 5})
	r := gin.New()
	NewAPI(svc, token).Mount(r)
	return r
}

// call sends a request as if from `remote`, addressed to `host`.
func call(h http.Handler, method, path, body, remote, host string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remote
	req.Host = host
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// local is a call from this machine to this machine.
func local(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	return call(h, method, path, body, "127.0.0.1:50000", "127.0.0.1:8081", nil)
}

// TestGuardKeepsStrangersOut checks the money-moving endpoints refuse anyone
// but this machine when no token is set, including a forged forwarding header
// and a rebinding page that reaches loopback under a foreign name.
func TestGuardKeepsStrangersOut(t *testing.T) {
	h := newTestAPI(t, "")

	if rec := local(h, "GET", "/pob/status", ""); rec.Code != http.StatusOK {
		t.Fatalf("loopback status = %d: %s", rec.Code, rec.Body)
	}
	if rec := call(h, "GET", "/pob/status", "", "203.0.113.9:4000", "node.example:8081", nil); rec.Code != http.StatusForbidden {
		t.Errorf("remote caller = %d, want 403", rec.Code)
	}
	forged := map[string]string{"X-Forwarded-For": "127.0.0.1"}
	if rec := call(h, "GET", "/pob/status", "", "203.0.113.9:4000", "127.0.0.1:8081", forged); rec.Code != http.StatusForbidden {
		t.Errorf("forged X-Forwarded-For = %d, want 403", rec.Code)
	}
	if rec := call(h, "GET", "/pob/status", "", "127.0.0.1:50000", "attacker.example:8081", nil); rec.Code != http.StatusForbidden {
		t.Errorf("rebinding host = %d, want 403", rec.Code)
	}
	if rec := call(h, "POST", "/pob/plan", `{}`, "127.0.0.1:50000", "localhost:8081", map[string]string{"Content-Type": "text/plain"}); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("non-JSON write = %d, want 415", rec.Code)
	}
	// The page itself is static and stays open.
	if rec := call(h, "GET", "/", "", "203.0.113.9:4000", "node.example:8081", nil); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "Proof of Buy") {
		t.Errorf("index = %d", rec.Code)
	}
}

// TestGuardWithToken checks a token replaces the loopback rule.
func TestGuardWithToken(t *testing.T) {
	h := newTestAPI(t, "s3cret")
	remote := func(auth string) int {
		headers := map[string]string{}
		if auth != "" {
			headers["Authorization"] = auth
		}
		return call(h, "GET", "/pob/status", "", "203.0.113.9:4000", "node.example:8081", headers).Code
	}
	if got := remote(""); got != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", got)
	}
	if got := remote("Bearer nope"); got != http.StatusUnauthorized {
		t.Errorf("wrong token = %d, want 401", got)
	}
	if got := remote("Bearer s3cret"); got != http.StatusOK {
		t.Errorf("right token = %d, want 200", got)
	}
}

// TestPlanEndpoint checks the preview: random by default, in CKB, and exact.
func TestPlanEndpoint(t *testing.T) {
	h := newTestAPI(t, "")
	rec := local(h, "POST", "/pob/plan", `{"from":20,"count":10,"total_ckb":"123.45678901"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("plan = %d: %s", rec.Code, rec.Body)
	}
	var out planOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Allocations) != 10 || out.TotalCKB != "123.45678901" || out.TotalShannon != "12345678901" {
		t.Errorf("plan = %+v", out)
	}
	if out.Allocations[0].AmountCKB == out.Allocations[1].AmountCKB &&
		out.Allocations[1].AmountCKB == out.Allocations[2].AmountCKB {
		t.Error("default mode should be random, but shares are identical")
	}

	bad := map[string]string{
		"junk amount":   `{"from":20,"count":2,"total_ckb":"lots"}`,
		"past heights":  `{"from":3,"count":2,"total_ckb":"10"}`,
		"unknown mode":  `{"mode":"wild","from":20,"count":2,"total_ckb":"10"}`,
		"bad spread":    `{"from":20,"count":2,"total_ckb":"10","spread_percent":100}`,
		"manual dupes":  `{"mode":"manual","allocations":[{"height":30,"amount_ckb":"1"},{"height":30,"amount_ckb":"1"}]}`,
		"manual amount": `{"mode":"manual","allocations":[{"height":30,"amount_ckb":"-1"}]}`,
	}
	for name, body := range bad {
		if rec := local(h, "POST", "/pob/plan", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, rec.Code)
		}
	}
}

// TestPrepayEndpointNeverLeaksOpenings drives prepay through the API and
// checks the listing shows amounts and states but not blinding factors.
func TestPrepayEndpointNeverLeaksOpenings(t *testing.T) {
	h := newTestAPI(t, "")
	rec := local(h, "POST", "/pob/prepay",
		`{"mode":"manual","allocations":[{"height":20,"amount_ckb":"10.5"},{"height":21,"amount_ckb":"4.5"}],"auto_declare":false}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("prepay = %d: %s", rec.Code, rec.Body)
	}
	var p prepaymentView
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.TotalCKB != "15" || len(p.Bids) != 2 || p.Bids[0].AmountCKB != "10.5" {
		t.Errorf("view = %+v", p)
	}

	list := local(h, "GET", "/pob/prepayments", "")
	if strings.Contains(list.Body.String(), "random") {
		t.Errorf("the listing exposes blinding factors: %s", list.Body)
	}

	// The same heights again are refused.
	if rec := local(h, "POST", "/pob/prepay", `{"from":20,"count":2,"total_ckb":"1"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("overlapping prepay = %d, want 400", rec.Code)
	}
}

// TestPrepayWithoutWalletIs503 checks the mock-L1 node reports why it cannot
// spend rather than pretending.
func TestPrepayWithoutWalletIs503(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, _, _ := newTestService(t, nil)
	r := gin.New()
	NewAPI(svc, "").Mount(r)
	if rec := local(r, "POST", "/pob/prepay", `{"from":20,"count":2,"total_ckb":"10"}`); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("prepay = %d, want 503", rec.Code)
	}
}
