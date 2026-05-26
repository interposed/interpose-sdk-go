// Package interpose is the cooperative-agent client for the interpose
// daemon. Agents call RequestPermission (or one of the typed helpers)
// before performing a gated action; the daemon either auto-allows under
// policy, prompts the user for hardware-backed approval, or denies.
//
// Quick start:
//
//	c, err := interpose.New("my-agent")
//	if err != nil { return err }
//	if err := c.RequestFileWrite(ctx, "/tmp/output.txt"); err != nil {
//	    return err  // user denied or daemon unreachable
//	}
//	// approved — proceed with the write
package interpose

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/interposehq/interpose/pkg/aauth"
)

// DefaultAddr is the address the SDK connects to when neither WithAddr
// nor the INTERPOSE_ADDR env var supply one.
const DefaultAddr = "127.0.0.1:7421"

// Client connects to a local interpose daemon and requests permission
// for agent actions. One Client per agent process; safe for concurrent
// use across goroutines.
type Client struct {
	addr  string
	agent *aauth.Agent
	http  *http.Client
}

// Option configures a Client. See WithAddr, WithHTTPClient, WithTimeout.
type Option func(*Client)

// WithAddr overrides the daemon address (host:port form). Precedence:
// explicit WithAddr > INTERPOSE_ADDR env var > DefaultAddr.
func WithAddr(addr string) Option {
	return func(c *Client) { c.addr = addr }
}

// WithHTTPClient injects a custom http.Client. Useful for tests, custom
// transports, or shared connection pools. The default client has a 5
// minute timeout — long enough to wait for a hardware-authenticator
// touch but short enough to detect a dead broker.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithTimeout sets the HTTP client timeout. Overrides the default 5 min.
// Use a context with a deadline for finer per-call control.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if c.http == nil {
			c.http = &http.Client{}
		}
		c.http.Timeout = d
	}
}

// New creates a Client for an agent with the given name. agentName is a
// human-readable label that appears in the audit log (e.g. "claude-code",
// "research-bot-v2"). A fresh Ed25519 keypair is generated per-process —
// agent identities are instance-scoped per the AAuth spec; the SDK does
// not persist agent keys.
//
// Returns an error if agentName is empty or key generation fails. Does
// NOT contact the daemon — connection happens lazily on the first
// RequestPermission call.
func New(agentName string, opts ...Option) (*Client, error) {
	if agentName == "" {
		return nil, fmt.Errorf("%w: agentName is required", ErrInvalidRequest)
	}
	addr := os.Getenv("INTERPOSE_ADDR")
	if addr == "" {
		addr = DefaultAddr
	}
	hostname, _ := os.Hostname()
	agent, err := aauth.NewLocalAgent(agentName, hostname, "http://"+addr)
	if err != nil {
		return nil, fmt.Errorf("create agent identity: %w", err)
	}
	c := &Client{
		addr:  addr,
		agent: agent,
		http:  &http.Client{Timeout: 5 * time.Minute},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// AgentID returns the AAuth-scheme agent identifier this client uses.
// Format: "aauth:<name>@<hostname>". Useful for log lines and for
// matching audit log entries.
func (c *Client) AgentID() string { return c.agent.ID }

// RequestPermission is the underlying primitive: synchronously asks the
// daemon to gate an action. Blocks until the user approves, denies, or
// the context cancels.
//
// scope is a string the broker policy understands. Standard scopes:
//
//	"file.read"   "file.write"   "file.delete"
//	"exec"        "net.connect"
//
// Custom scopes are fine if your broker policy is configured for them.
//
// target is the resource the action operates on (file path, "host:port",
// binary path, etc.). The interpretation is scope-dependent.
//
// Returns nil on approval. Returns ErrDenied on user denial or policy
// auto-deny. Returns ErrDaemonUnreachable for transport failures.
func (c *Client) RequestPermission(ctx context.Context, scope, target string) error {
	if scope == "" || target == "" {
		return fmt.Errorf("%w: scope and target are required", ErrInvalidRequest)
	}
	tok, err := c.agent.MintToken()
	if err != nil {
		return fmt.Errorf("mint agent token: %w", err)
	}
	body, _ := json.Marshal(struct {
		Scope         string `json:"scope"`
		Target        string `json:"target"`
		Justification string `json:"justification,omitempty"`
		PID           int    `json:"pid"`
	}{
		Scope:  scope,
		Target: target,
		PID:    os.Getpid(),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://"+c.addr+"/permission", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "AAuth "+tok)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusForbidden:
		var body struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return fmt.Errorf("%w: %s", ErrDenied, body.Reason)
	case http.StatusUnauthorized:
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%w: %s", ErrUnauthorized, string(b))
	case http.StatusBadRequest:
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%w: %s", ErrInvalidRequest, string(b))
	default:
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected broker response %d: %s", resp.StatusCode, string(b))
	}
}

// Typed helpers — thin wrappers over RequestPermission with the right
// scope baked in. Use these for discoverability and to avoid scope typos.
// Agents using custom scopes should call RequestPermission directly.

// RequestFileWrite gates an upcoming write/create to path.
func (c *Client) RequestFileWrite(ctx context.Context, path string) error {
	return c.RequestPermission(ctx, "file.write", path)
}

// RequestFileRead gates an upcoming read/open of path.
func (c *Client) RequestFileRead(ctx context.Context, path string) error {
	return c.RequestPermission(ctx, "file.read", path)
}

// RequestFileDelete gates an upcoming unlink/rmdir of path.
func (c *Client) RequestFileDelete(ctx context.Context, path string) error {
	return c.RequestPermission(ctx, "file.delete", path)
}

// RequestExec gates an upcoming exec of binary (absolute path).
func (c *Client) RequestExec(ctx context.Context, binary string) error {
	return c.RequestPermission(ctx, "exec", binary)
}

// RequestConnect gates an upcoming TCP/UDP connect to host:port. host
// should be an IP address (resolve hostnames on the agent side before
// calling — the broker can't gate what it can't name).
func (c *Client) RequestConnect(ctx context.Context, host string, port int) error {
	return c.RequestPermission(ctx, "net.connect", fmt.Sprintf("%s:%d", host, port))
}
