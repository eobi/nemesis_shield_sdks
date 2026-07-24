// Package nemesis is the Nemesis Shield — Sentinel client for Go.
//
// Wrap any net/http handler to observe request behavior:
//
//	mux := http.NewServeMux()
//	// ... register routes ...
//	handler := nemesis.Middleware(os.Getenv("NEMESIS_TOKEN"))(mux)
//	http.ListenAndServe(":8080", handler)
//
// It reports only privacy-preserving metadata (method, path shape, status, whether authenticated)
// to Nemesis Shield. It never ships request bodies. Fail-open: Nemesis being unreachable never
// affects your app.
package nemesis

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const ObserveURL = "https://shield.nemesislabs.xyz/api/v1/observe"

var httpClient = &http.Client{Timeout: 2 * time.Second}

type Event struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Status        int    `json:"status"`
	Authenticated bool   `json:"authenticated"`
}

var (
	reInt  = regexp.MustCompile(`^\d+$`)
	reUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reHex  = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
)

// PathShape collapses IDs so the baseline doesn't explode: /orders/123 -> /orders/{int}.
func PathShape(path string) string {
	path = strings.SplitN(path, "?", 2)[0]
	segs := strings.Split(path, "/")
	for i, s := range segs {
		switch {
		case reInt.MatchString(s):
			segs[i] = "{int}"
		case reUUID.MatchString(s):
			segs[i] = "{uuid}"
		case reHex.MatchString(s):
			segs[i] = "{hex}"
		}
	}
	return strings.Join(segs, "/")
}

// Report ships a batch of events. Fire-and-forget; never blocks meaningfully; ignores errors.
func Report(token string, events []Event) {
	if token == "" || len(events) == 0 {
		return
	}
	body, _ := json.Marshal(map[string]any{"events": events})
	req, err := http.NewRequest("POST", ObserveURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if resp, err := httpClient.Do(req); err == nil {
		resp.Body.Close()
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) { r.status = code; r.ResponseWriter.WriteHeader(code) }

// Middleware wraps an http.Handler and reports each request after it completes.
func Middleware(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w, status: 200}
			next.ServeHTTP(rec, r)
			authed := r.Header.Get("Authorization") != "" || len(r.Cookies()) > 0
			go Report(token, []Event{{Method: r.Method, Path: PathShape(r.URL.Path), Status: rec.status, Authenticated: authed}})
		})
	}
}
