// Package nemesis is the Nemesis Shield — Sentinel SDK for Go (native: local shape + policy cache +
// inline blocking). Learns your app's normal behavior; in enforce mode blocks off-baseline requests
// (auth bypass, path traversal, scanners, unusual methods) before your handlers run. Fail-open.
//
//	client := nemesis.New(os.Getenv("NEMESIS_TOKEN"))
//	handler := client.Middleware(mux)     // net/http (works with chi too)
//	http.ListenAndServe(":8080", handler)
//
// Ships only method + route shape + auth — never bodies or secrets.
package nemesis

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const defaultEndpoint = "https://shield.nemesislabs.xyz/api/v1/sketches"

// Safe-unlock (break-glass): paths never blocked, so a still-learning baseline can't lock operators
// out of the doors they need to fix it. Prefix-matched on the pathname. Override/extend with the
// NEMESIS_SHIELD_BOOTSTRAP env (comma-separated).
var defaultBootstrap = []string{"/login", "/signin", "/sign-in", "/auth", "/oauth", "/session", "/wp-login.php", "/wp-admin"}

func bootstrapPaths() []string {
	if env := strings.TrimSpace(os.Getenv("NEMESIS_SHIELD_BOOTSTRAP")); env != "" {
		var out []string
		for _, p := range strings.Split(env, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return defaultBootstrap
}

// NeverBlock reports whether this path is on the never-block bootstrap allow-list (prefix match).
func NeverBlock(path string) bool {
	p := strings.ToLower(path)
	for _, b := range bootstrapPaths() {
		if b != "" && strings.HasPrefix(p, strings.ToLower(b)) {
			return true
		}
	}
	return false
}

// Canonical value taxonomy — must match the shared engine (tokenize.ts) so a Go app and a
// Node/Python app produce identical shape hashes.
var (
	reInt   = regexp.MustCompile(`^-?\d+$`)
	reFloat = regexp.MustCompile(`^-?\d*\.\d+$`)
	reUUID  = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reEmail = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	reURL   = regexp.MustCompile(`(?i)^https?://\S+$`)
	reIPv4  = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	reIPv6  = regexp.MustCompile(`(?i)^[0-9a-f:]+:[0-9a-f:]+$`)
	reDate  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?`)
	reJWT   = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	reHex   = regexp.MustCompile(`(?i)^[0-9a-f]+$`)
	reB64   = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	reAlpha = regexp.MustCompile(`^[A-Za-z]+$`)
	reAlnum = regexp.MustCompile(`^[A-Za-z0-9]+$`)
	// A run of 7+ letters => reads like a word / route name, not an opaque id/token.
	reWord = regexp.MustCompile(`[A-Za-z]{7,}`)
)

// Param is a query-parameter shape (name + kind, never the value).
type Param struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// Sketch is a privacy-preserving request signature.
type Sketch struct {
	Route         string  `json:"route"`
	Method        string  `json:"method"`
	Authenticated bool    `json:"authenticated"`
	Status        int     `json:"status"`
	Params        []Param `json:"params"`
	Shape         string  `json:"shape"`
}

// Client caches the compiled policy and makes fast offline decisions; ships telemetry async.
type Client struct {
	token, endpoint string
	http            *http.Client

	mu           sync.RWMutex
	mode         string
	shapes       map[string]string // shape -> "allow"|"block"
	knownBad     map[string]bool
	haveBaseline bool
	buffer       []Sketch
}

// New creates a client and starts the background policy poller (console-driven enforce, no redeploy).
func New(token string) *Client { return NewWithEndpoint(token, defaultEndpoint) }

func NewWithEndpoint(token, endpoint string) *Client {
	c := &Client{
		token: token, endpoint: endpoint,
		http:     &http.Client{Timeout: 3 * time.Second},
		mode:     "observe",
		shapes:   map[string]string{},
		knownBad: map[string]bool{},
	}
	if token != "" {
		c.refresh()
		go func() {
			t := time.NewTicker(2 * time.Second)
			for range t.C {
				c.flush()
				c.refresh()
			}
		}()
	}
	return c
}

func normalizePath(path string) string {
	path = strings.SplitN(path, "?", 2)[0]
	path = strings.SplitN(path, "#", 2)[0]
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if s == "" {
			continue
		}
		if strings.Contains(s, "..") {
			segs[i] = "{traversal}" // path-traversal segment (also keeps ".." out of telemetry)
			continue
		}
		switch kindOf(s) {
		case "int", "float":
			segs[i] = "{int}"
		case "uuid":
			segs[i] = "{uuid}"
		case "hex":
			segs[i] = "{hex}"
		case "base64":
			segs[i] = "{token}"
		case "alnum":
			if len(s) >= 12 && !reWord.MatchString(s) {
				segs[i] = "{id}"
			}
		}
	}
	out := strings.Join(segs, "/")
	if out == "" {
		return "/"
	}
	return out
}

func kindOf(v string) string {
	if v == "" {
		return "empty"
	}
	switch {
	case reUUID.MatchString(v):
		return "uuid"
	case reEmail.MatchString(v):
		return "email"
	case reURL.MatchString(v):
		return "url"
	case reIPv4.MatchString(v):
		return "ipv4"
	case reIPv6.MatchString(v):
		return "ipv6"
	case reJWT.MatchString(v):
		return "jwt"
	case reDate.MatchString(v):
		return "date"
	case reInt.MatchString(v):
		return "int"
	case reFloat.MatchString(v):
		return "float"
	case len(v) >= 16 && reHex.MatchString(v):
		return "hex"
	case len(v) >= 16 && reB64.MatchString(v) && !reWord.MatchString(v):
		return "base64"
	case reAlpha.MatchString(v):
		return "alpha"
	case reAlnum.MatchString(v):
		return "alnum"
	default:
		return "string"
	}
}

func fnv1a(s string) string {
	var h uint32 = 0x811c9dc5
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 0x01000193
	}
	const hexdig = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = hexdig[h&0xf]
		h >>= 4
	}
	return string(out)
}

// Analytics / click-tracking query params carry no application logic and are the main cause of shape
// explosion (every ad/campaign link adds different ones). Stripped from the signature so a UTM'd
// request matches the bare route, while real params (and any attack in them) stay modeled. Shared,
// identical across every Nemesis Shield SDK so the shape hash matches everywhere.
var trackingPrefixes = []string{"utm_", "mtm_", "pk_", "hsa_", "matomo_", "piwik_", "ga_"}
var trackingExact = map[string]bool{"gclid": true, "gbraid": true, "wbraid": true, "dclid": true, "gclsrc": true, "fbclid": true, "msclkid": true, "twclid": true, "ttclid": true, "yclid": true, "igshid": true, "scid": true, "wickedid": true, "_ga": true, "_gl": true, "_hsenc": true, "_hsmi": true, "mc_cid": true, "mc_eid": true, "vero_id": true, "vero_conv": true, "oly_anon_id": true, "oly_enc_id": true, "_openstat": true, "rb_clickid": true, "s_cid": true, "epik": true, "sccid": true}

func isTrackingParam(name string) bool {
	n := strings.ToLower(name)
	for _, p := range trackingPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return trackingExact[n]
}

// BuildSketch computes the request signature. query may be nil.
func (c *Client) BuildSketch(method, path string, query map[string][]string, authed bool, status int) Sketch {
	route := normalizePath(path)
	params := make([]Param, 0, len(query))
	names := make([]string, 0, len(query))
	for k := range query {
		if isTrackingParam(k) {
			continue
		}
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v := ""
		if len(query[k]) > 0 {
			v = query[k][0]
		}
		params = append(params, Param{Name: k, Kind: kindOf(v)})
	}
	// canonical shape input: params are [name, kind, nested]; json.Marshal sorts the map keys
	// (auth, method, params, route); status is excluded so enforcement decides pre-response.
	canonParams := make([][]any, len(params))
	for i, p := range params {
		canonParams[i] = []any{p.Name, p.Kind, 0}
	}
	auth := 0
	if authed {
		auth = 1
	}
	canon, _ := json.Marshal(map[string]any{"route": route, "method": strings.ToUpper(method), "params": canonParams, "auth": auth})
	return Sketch{Route: route, Method: strings.ToUpper(method), Authenticated: authed, Status: status, Params: params, Shape: fnv1a(string(canon))}
}

// Decide is the positive-security verdict.
func (c *Client) Decide(s Sketch) (block bool, reason string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	switch c.shapes[s.Shape] {
	case "allow":
		return false, ""
	case "block":
		return true, "policy: blocked shape"
	}
	if c.knownBad[s.Shape] {
		return true, "global threat intelligence"
	}
	if c.haveBaseline {
		return true, "off-baseline: unapproved behavior"
	}
	return false, ""
}

func (c *Client) Enforcing() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.mode == "enforce" }

// Record buffers a sketch for async shipment.
func (c *Client) Record(s Sketch) {
	c.mu.Lock()
	c.buffer = append(c.buffer, s)
	full := len(c.buffer) >= 50
	c.mu.Unlock()
	if full {
		c.flush()
	}
}

func (c *Client) flush() {
	c.mu.Lock()
	if len(c.buffer) == 0 {
		c.mu.Unlock()
		return
	}
	batch := c.buffer
	c.buffer = nil
	c.mu.Unlock()
	c.send(batch)
}

func (c *Client) refresh() { c.send([]Sketch{}) }

func (c *Client) send(batch []Sketch) {
	body, _ := json.Marshal(map[string]any{"sketches": batch})
	req, err := http.NewRequest("POST", c.endpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var out struct {
		Mode   string `json:"mode"`
		Policy struct {
			Shapes   map[string]string `json:"shapes"`
			KnownBad []string          `json:"knownBad"`
		} `json:"policy"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return
	}
	c.mu.Lock()
	if out.Mode != "" {
		c.mode = out.Mode
	}
	if out.Policy.Shapes != nil {
		c.shapes = out.Policy.Shapes
		if len(out.Policy.Shapes) > 0 {
			c.haveBaseline = true
		}
	}
	if out.Policy.KnownBad != nil {
		c.knownBad = map[string]bool{}
		for _, s := range out.Policy.KnownBad {
			c.knownBad[s] = true
		}
	}
	c.mu.Unlock()
}

func authedFrom(r *http.Request) bool {
	return r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Api-Key") != ""
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) { r.status = code; r.ResponseWriter.WriteHeader(code) }

// Middleware wraps a net/http handler (also works with chi). Blocks off-baseline in enforce mode.
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authed := authedFrom(r)
		if c.Enforcing() && !NeverBlock(r.URL.Path) {
			s := c.BuildSketch(r.Method, r.URL.Path, r.URL.Query(), authed, 0)
			if block, reason := c.Decide(s); block {
				c.Record(c.BuildSketch(r.Method, r.URL.Path, r.URL.Query(), authed, 403))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "blocked_by_nemesis_shield", "reason": reason})
				return
			}
		}
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		c.Record(c.BuildSketch(r.Method, r.URL.Path, r.URL.Query(), authed, rec.status))
	})
}
