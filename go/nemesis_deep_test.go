package nemesis

// Deep coverage test - drives the real net/http Middleware end to end and proves the Go SDK SEES an
// attacker's request from ANY route and blocks it in enforce mode: unknown paths, injected/extra
// query params, param-type / method / auth anomalies, knownBad. Also proves the safe-unlock (never
// block the login/auth path) and fail-open (no baseline). Run: go test ./...

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
}

// A client whose policy we set directly (no network) - exactly what the middleware holds at runtime.
func clientWith(mode string, allow []string, knownBad []string) *Client {
	c := &Client{
		endpoint: defaultEndpoint,
		http:     &http.Client{},
		mode:     mode,
		shapes:   map[string]string{},
		knownBad: map[string]bool{},
	}
	for _, s := range allow {
		c.shapes[s] = "allow"
	}
	for _, s := range knownBad {
		c.knownBad[s] = true
	}
	c.haveBaseline = len(allow) > 0 || len(knownBad) > 0
	return c
}

func shapeOf(c *Client, method, rawurl string, authed bool) string {
	u, _ := url.Parse(rawurl)
	return c.BuildSketch(method, u.Path, u.Query(), authed, 0).Shape
}

func blocked(c *Client, method, rawurl string, authed bool) bool {
	u, _ := url.Parse(rawurl)
	req := httptest.NewRequest(method, u.String(), nil)
	if authed {
		req.Header.Set("Authorization", "Bearer x")
	}
	rec := httptest.NewRecorder()
	c.Middleware(okHandler()).ServeHTTP(rec, req)
	return rec.Code == http.StatusForbidden
}

func baselineClient(mode string, extraKnownBad ...string) *Client {
	ref := clientWith(mode, nil, nil)
	allow := []string{
		shapeOf(ref, "GET", "/", false),
		shapeOf(ref, "GET", "/products/12345", false),
		shapeOf(ref, "GET", "/search?q=shoes", false),
		shapeOf(ref, "POST", "/api/orders", true),
	}
	return clientWith(mode, allow, extraKnownBad)
}

func TestQueryParamsChangeShape(t *testing.T) {
	c := clientWith("enforce", nil, nil)
	if shapeOf(c, "GET", "/search?q=x", false) == shapeOf(c, "GET", "/search?q=x&inject=1", false) {
		t.Fatal("adding a param should change the shape")
	}
	if shapeOf(c, "GET", "/search?q=shoes", false) == shapeOf(c, "GET", "/search?q=%27+OR+1%3D1", false) {
		t.Fatal("param kind change should change the shape")
	}
}

func TestEnforceBlocksAttacksFromAnyRoute(t *testing.T) {
	c := baselineClient("enforce")
	pass := []struct {
		m, u  string
		authed bool
	}{
		{"GET", "/", false}, {"GET", "/products/999", false},
		{"GET", "/search?q=boots", false}, {"POST", "/api/orders", true},
	}
	for _, p := range pass {
		if blocked(c, p.m, p.u, p.authed) {
			t.Errorf("approved %s %s should pass", p.m, p.u)
		}
	}
	attacks := []struct {
		name, m, u string
		authed     bool
	}{
		{"scanner /.env", "GET", "/.env", false},
		{"scanner bak", "GET", "/wp-config.php.bak", false},
		{"injected param", "GET", "/search?q=x&cmd=id", false},
		{"sqli kind", "GET", "/search?q=%27+OR+1%3D1--", false},
		{"method anomaly", "POST", "/", false},
		{"auth anomaly", "GET", "/api/orders", false},
		{"unknown admin", "GET", "/admin/config", false},
	}
	for _, a := range attacks {
		if !blocked(c, a.m, a.u, a.authed) {
			t.Errorf("attack %q (%s %s) should be blocked", a.name, a.m, a.u)
		}
	}
}

func TestKnownBadBlocked(t *testing.T) {
	ref := clientWith("enforce", nil, nil)
	bad := shapeOf(ref, "POST", "/xmlrpc.php", false)
	c := baselineClient("enforce", bad)
	if !blocked(c, "POST", "/xmlrpc.php", false) {
		t.Error("knownBad shape should be blocked")
	}
}

func TestSafeUnlockNeverBlocksAuthPath(t *testing.T) {
	c := baselineClient("enforce")
	for _, p := range []string{"/login?next=x", "/wp-login.php", "/wp-admin/options.php"} {
		if blocked(c, "POST", p, false) {
			t.Errorf("auth path %s must never be blocked", p)
		}
	}
}

func TestFailOpenNoBaseline(t *testing.T) {
	c := clientWith("enforce", nil, nil)
	if blocked(c, "GET", "/.env", false) {
		t.Error("must fail open with no baseline")
	}
}

func TestObserveModeNeverBlocks(t *testing.T) {
	c := baselineClient("observe")
	if blocked(c, "GET", "/.env", false) {
		t.Error("observe mode must never block")
	}
}
