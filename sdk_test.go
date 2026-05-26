package interpose_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	interpose "github.com/interposehq/interpose-sdk-go"
)

// fakeBroker is an httptest.Server with a recorded request log and a
// configurable next-response. Cleanup is registered with t so a panicking
// test still tears down the server.
type fakeBroker struct {
	t        *testing.T
	server   *httptest.Server
	mu       sync.Mutex
	requests []recordedReq
	respond  func(w http.ResponseWriter)
}

type recordedReq struct {
	Method      string
	Path        string
	Auth        string
	ContentType string
	Body        map[string]any
}

func newFakeBroker(t *testing.T) *fakeBroker {
	t.Helper()
	f := &fakeBroker{
		t: t,
		respond: func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w,
				`{"auth_token":"fake-auth-jwt","expires_in":60,"scope":"file.write"}`)
		},
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.requests = append(f.requests, recordedReq{
			Method:      r.Method,
			Path:        r.URL.Path,
			Auth:        r.Header.Get("Authorization"),
			ContentType: r.Header.Get("Content-Type"),
			Body:        body,
		})
		respond := f.respond
		f.mu.Unlock()
		respond(w)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeBroker) addr() string {
	return strings.TrimPrefix(f.server.URL, "http://")
}

func (f *fakeBroker) setRespond(fn func(w http.ResponseWriter)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.respond = fn
}

func (f *fakeBroker) reqs() []recordedReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recordedReq, len(f.requests))
	copy(out, f.requests)
	return out
}

// newClient constructs a Client pointed at the fake broker. Fails the
// test if construction errors.
func newClient(t *testing.T, f *fakeBroker, extra ...interpose.Option) *interpose.Client {
	t.Helper()
	opts := append([]interpose.Option{interpose.WithAddr(f.addr())}, extra...)
	c, err := interpose.New("test-agent", opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// ----------------------------------------------------------------------------
// New / construction
// ----------------------------------------------------------------------------

func TestNew_requiresAgentName(t *testing.T) {
	_, err := interpose.New("")
	if err == nil {
		t.Fatal("New(\"\") returned nil error, want ErrInvalidRequest")
	}
	if !errors.Is(err, interpose.ErrInvalidRequest) {
		t.Errorf("error = %v, want errors.Is(..., ErrInvalidRequest)", err)
	}
}

func TestNew_defaultAddr(t *testing.T) {
	// Clear env so we test the constant default.
	t.Setenv("INTERPOSE_ADDR", "")
	c, err := interpose.New("test-agent")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// AgentID format is "aauth:<name>@<host>" — verifies New() set up the
	// agent identity without requiring a live broker.
	if !strings.HasPrefix(c.AgentID(), "aauth:test-agent@") {
		t.Errorf("AgentID = %q, want aauth:test-agent@... prefix", c.AgentID())
	}
}

func TestNew_envAddr(t *testing.T) {
	f := newFakeBroker(t)
	t.Setenv("INTERPOSE_ADDR", f.addr())
	c, err := interpose.New("test-agent") // no WithAddr — must pick up env
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.RequestPermission(context.Background(), "file.write", "/tmp/x"); err != nil {
		t.Fatalf("RequestPermission: %v", err)
	}
	if n := len(f.reqs()); n != 1 {
		t.Fatalf("fake broker saw %d requests, want 1 (env var ignored?)", n)
	}
}

func TestNew_optionsOverrideEnv(t *testing.T) {
	t.Setenv("INTERPOSE_ADDR", "ignored.example:9999")
	f := newFakeBroker(t)
	c := newClient(t, f) // WithAddr inside newClient takes precedence
	if err := c.RequestPermission(context.Background(), "file.write", "/tmp/x"); err != nil {
		t.Fatalf("RequestPermission: %v", err)
	}
	if len(f.reqs()) != 1 {
		t.Fatalf("fake broker got %d requests, want 1", len(f.reqs()))
	}
}

// ----------------------------------------------------------------------------
// RequestPermission — happy path + body shape + headers
// ----------------------------------------------------------------------------

func TestRequestPermission_approves(t *testing.T) {
	f := newFakeBroker(t)
	c := newClient(t, f)

	if err := c.RequestPermission(context.Background(), "file.write", "/tmp/foo"); err != nil {
		t.Fatalf("RequestPermission: %v", err)
	}

	reqs := f.reqs()
	if len(reqs) != 1 {
		t.Fatalf("got %d requests, want 1", len(reqs))
	}
	r := reqs[0]
	if r.Method != http.MethodPost {
		t.Errorf("method = %s, want POST", r.Method)
	}
	if r.Path != "/permission" {
		t.Errorf("path = %s, want /permission", r.Path)
	}
	if r.ContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", r.ContentType)
	}
	if !strings.HasPrefix(r.Auth, "AAuth ") {
		t.Errorf("Authorization = %q, want AAuth prefix", r.Auth)
	}
	if got := r.Body["scope"]; got != "file.write" {
		t.Errorf("body.scope = %v, want file.write", got)
	}
	if got := r.Body["target"]; got != "/tmp/foo" {
		t.Errorf("body.target = %v, want /tmp/foo", got)
	}
	// PID is JSON-decoded as float64.
	pid, _ := r.Body["pid"].(float64)
	if int(pid) != os.Getpid() {
		t.Errorf("body.pid = %v, want %d", pid, os.Getpid())
	}
}

func TestRequestPermission_signsTokenDifferentlyPerCall(t *testing.T) {
	// Each MintToken() call uses a fresh iat/exp, so the Authorization
	// header should differ between calls. Verifies the SDK isn't accidentally
	// caching a single token across requests.
	f := newFakeBroker(t)
	c := newClient(t, f)
	ctx := context.Background()
	_ = c.RequestPermission(ctx, "file.write", "/tmp/a")
	time.Sleep(1100 * time.Millisecond) // ensure iat changes (JWT exp/iat are second-granularity)
	_ = c.RequestPermission(ctx, "file.write", "/tmp/b")
	reqs := f.reqs()
	if len(reqs) != 2 {
		t.Fatalf("got %d requests, want 2", len(reqs))
	}
	if reqs[0].Auth == reqs[1].Auth {
		t.Errorf("two calls sent identical Authorization header: %s", reqs[0].Auth)
	}
}

// ----------------------------------------------------------------------------
// RequestPermission — error mapping
// ----------------------------------------------------------------------------

func TestRequestPermission_denied(t *testing.T) {
	f := newFakeBroker(t)
	f.setRespond(func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"denied","reason":"policy.deny:no-shadow-access"}`)
	})
	c := newClient(t, f)
	err := c.RequestPermission(context.Background(), "file.read", "/etc/shadow")
	if !errors.Is(err, interpose.ErrDenied) {
		t.Fatalf("expected ErrDenied, got %v", err)
	}
	if !strings.Contains(err.Error(), "policy.deny:no-shadow-access") {
		t.Errorf("error message %q missing reason from broker", err)
	}
}

func TestRequestPermission_unauthorized(t *testing.T) {
	f := newFakeBroker(t)
	f.setRespond(func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"unauthorized","reason":"token-expired"}`)
	})
	c := newClient(t, f)
	err := c.RequestPermission(context.Background(), "exec", "/bin/sh")
	if !errors.Is(err, interpose.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestRequestPermission_invalidRequest_fromBroker(t *testing.T) {
	f := newFakeBroker(t)
	f.setRespond(func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_request","reason":"scope unknown"}`)
	})
	c := newClient(t, f)
	err := c.RequestPermission(context.Background(), "weird.scope", "/x")
	if !errors.Is(err, interpose.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

func TestRequestPermission_invalidRequest_clientSide(t *testing.T) {
	f := newFakeBroker(t)
	c := newClient(t, f)
	err := c.RequestPermission(context.Background(), "", "/x")
	if !errors.Is(err, interpose.ErrInvalidRequest) {
		t.Fatalf("empty scope: want ErrInvalidRequest, got %v", err)
	}
	err = c.RequestPermission(context.Background(), "file.write", "")
	if !errors.Is(err, interpose.ErrInvalidRequest) {
		t.Fatalf("empty target: want ErrInvalidRequest, got %v", err)
	}
	// Neither call should have hit the broker.
	if n := len(f.reqs()); n != 0 {
		t.Errorf("got %d requests on client-side validation failures, want 0", n)
	}
}

func TestRequestPermission_daemonUnreachable(t *testing.T) {
	// Reserve a port (probably none listening on that port).
	c, err := interpose.New("test-agent", interpose.WithAddr("127.0.0.1:1")) // port 1 is reserved and won't be listening
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = c.RequestPermission(ctx, "file.write", "/tmp/x")
	if !errors.Is(err, interpose.ErrDaemonUnreachable) {
		t.Fatalf("expected ErrDaemonUnreachable, got %v", err)
	}
}

func TestRequestPermission_unexpectedStatus(t *testing.T) {
	f := newFakeBroker(t)
	f.setRespond(func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "upstream broken")
	})
	c := newClient(t, f)
	err := c.RequestPermission(context.Background(), "file.write", "/tmp/x")
	if err == nil {
		t.Fatal("expected error on 502, got nil")
	}
	// Should NOT be one of the typed errors — unexpected status falls
	// through to a bare error.
	if errors.Is(err, interpose.ErrDenied) ||
		errors.Is(err, interpose.ErrUnauthorized) ||
		errors.Is(err, interpose.ErrDaemonUnreachable) ||
		errors.Is(err, interpose.ErrInvalidRequest) {
		t.Errorf("unexpected typed error for 502: %v", err)
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error message %q missing status code", err)
	}
}

func TestRequestPermission_contextCancel(t *testing.T) {
	// Broker that hangs until either the per-request context cancels (the
	// happy path we're testing) or the test cleanup closes `done` (so the
	// server's in-flight handler returns and httptest.Close doesn't hang).
	done := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-done:
		}
	}))
	t.Cleanup(func() {
		close(done)
		hang.Close()
	})
	c, err := interpose.New("test-agent",
		interpose.WithAddr(strings.TrimPrefix(hang.URL, "http://")))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = c.RequestPermission(ctx, "file.write", "/tmp/x")
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	// http.Client wraps context errors as net errors; ErrDaemonUnreachable
	// is the right typed match.
	if !errors.Is(err, interpose.ErrDaemonUnreachable) {
		t.Errorf("ctx cancel: expected ErrDaemonUnreachable wrapper, got %v", err)
	}
}

// ----------------------------------------------------------------------------
// Typed helpers — verify each maps to the right scope/target
// ----------------------------------------------------------------------------

func TestTypedHelpers_scopesAndTargets(t *testing.T) {
	cases := []struct {
		name       string
		call       func(c *interpose.Client) error
		wantScope  string
		wantTarget string
	}{
		{
			name:       "RequestFileWrite",
			call:       func(c *interpose.Client) error { return c.RequestFileWrite(context.Background(), "/tmp/w") },
			wantScope:  "file.write",
			wantTarget: "/tmp/w",
		},
		{
			name:       "RequestFileRead",
			call:       func(c *interpose.Client) error { return c.RequestFileRead(context.Background(), "/etc/passwd") },
			wantScope:  "file.read",
			wantTarget: "/etc/passwd",
		},
		{
			name:       "RequestFileDelete",
			call:       func(c *interpose.Client) error { return c.RequestFileDelete(context.Background(), "/tmp/d") },
			wantScope:  "file.delete",
			wantTarget: "/tmp/d",
		},
		{
			name:       "RequestExec",
			call:       func(c *interpose.Client) error { return c.RequestExec(context.Background(), "/usr/bin/curl") },
			wantScope:  "exec",
			wantTarget: "/usr/bin/curl",
		},
		{
			name:       "RequestConnect",
			call:       func(c *interpose.Client) error { return c.RequestConnect(context.Background(), "1.1.1.1", 443) },
			wantScope:  "net.connect",
			wantTarget: "1.1.1.1:443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeBroker(t)
			c := newClient(t, f)
			if err := tc.call(c); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			reqs := f.reqs()
			if len(reqs) != 1 {
				t.Fatalf("got %d requests, want 1", len(reqs))
			}
			if got := reqs[0].Body["scope"]; got != tc.wantScope {
				t.Errorf("scope = %v, want %s", got, tc.wantScope)
			}
			if got := reqs[0].Body["target"]; got != tc.wantTarget {
				t.Errorf("target = %v, want %s", got, tc.wantTarget)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Options
// ----------------------------------------------------------------------------

func TestWithHTTPClient_isUsed(t *testing.T) {
	f := newFakeBroker(t)
	calls := 0
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return http.DefaultTransport.RoundTrip(r)
	})
	c, err := interpose.New("test-agent",
		interpose.WithAddr(f.addr()),
		interpose.WithHTTPClient(&http.Client{Transport: rt, Timeout: 10 * time.Second}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.RequestPermission(context.Background(), "file.write", "/tmp/x"); err != nil {
		t.Fatalf("RequestPermission: %v", err)
	}
	if calls != 1 {
		t.Errorf("custom transport saw %d calls, want 1", calls)
	}
}

func TestWithTimeout_applied(t *testing.T) {
	// Server hangs for 500ms; client timeout is 100ms.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(slow.Close)
	c, err := interpose.New("test-agent",
		interpose.WithAddr(strings.TrimPrefix(slow.URL, "http://")),
		interpose.WithTimeout(100*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	start := time.Now()
	err = c.RequestPermission(context.Background(), "file.write", "/tmp/x")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 400*time.Millisecond {
		t.Errorf("WithTimeout(100ms) didn't fire — took %v", elapsed)
	}
}

// roundTripperFunc lets us pass a function as an http.RoundTripper.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Compile-time check that interpose.Option is exported and assignable.
var _ interpose.Option = interpose.WithAddr("x")

// Compile-time check that the package's exported errors are available.
var (
	_ = interpose.ErrDenied
	_ = interpose.ErrDaemonUnreachable
	_ = interpose.ErrUnauthorized
	_ = interpose.ErrInvalidRequest
)

// silence an unused-import warning on systems where net isn't otherwise needed
var _ = net.Listen
