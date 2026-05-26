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
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/interposehq/interpose/pkg/aauth"
	aauthclient "github.com/interposehq/interpose/pkg/aauth/client"
)

// DefaultAddr is the address the SDK connects to when neither WithAddr
// nor the INTERPOSE_ADDR env var supply one.
const DefaultAddr = "127.0.0.1:7421"

// Client connects to a local interpose daemon and requests permission
// for agent actions. One Client per agent process; safe for concurrent
// use across goroutines.
//
// Under the hood, Client delegates to interpose's pkg/aauth/client which
// implements the full AAuth wire protocol: ed25519 agent token minting,
// Signature-Key header, RFC 9421 HTTP Message Signatures, Content-Digest.
// The SDK exposes a small, opinionated API on top of that ceremony so
// agent code never has to think about JWTs or signatures.
type Client struct {
	aac *aauthclient.Client
	pid int
}

// Option configures a Client. See WithAddr, WithHTTPClient, WithTimeout.
type Option func(*Client)

// WithAddr overrides the daemon address (host:port form). Precedence:
// explicit WithAddr > INTERPOSE_ADDR env var > DefaultAddr.
func WithAddr(addr string) Option {
	return func(c *Client) { c.aac.PSBase = "http://" + addr }
}

// WithHTTPClient injects a custom http.Client. Useful for tests, custom
// transports, or shared connection pools. The default client has a 5
// minute timeout — long enough to wait for a hardware-authenticator
// touch but short enough to detect a dead broker.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.aac.HTTPClient = h }
}

// WithTimeout sets the HTTP client timeout. Overrides the default 5 min.
// Use a context with a deadline for finer per-call control.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if c.aac.HTTPClient == nil {
			c.aac.HTTPClient = &http.Client{}
		}
		c.aac.HTTPClient.Timeout = d
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
		aac: aauthclient.New("http://"+addr, agent),
		pid: os.Getpid(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// AgentID returns the AAuth-scheme agent identifier this client uses.
// Format: "aauth:<name>@<hostname>". Useful for log lines and for
// matching audit log entries on the broker side.
func (c *Client) AgentID() string { return c.aac.Agent.ID }

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
// auto-deny. Returns ErrUnauthorized if the broker rejected the agent
// token. Returns ErrInvalidRequest for bad input (caught either side).
// Returns ErrDaemonUnreachable for transport / signing failures.
func (c *Client) RequestPermission(ctx context.Context, scope, target string) error {
	if scope == "" || target == "" {
		return fmt.Errorf("%w: scope and target are required", ErrInvalidRequest)
	}
	res, err := c.aac.RequestPermission(ctx, aauthclient.PermissionRequest{
		Scope:  scope,
		Target: target,
		PID:    c.pid,
	})
	if err != nil {
		// Underlying client returns errors for network failures, agent-
		// token minting, and RFC 9421 signing. All three mean "we couldn't
		// get a verdict from the broker" — bundle as ErrDaemonUnreachable
		// rather than expose three sentinels for the same caller decision.
		return fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	if res.Approved {
		return nil
	}
	switch res.StatusCode {
	case http.StatusForbidden:
		return fmt.Errorf("%w: %s", ErrDenied, res.Reason)
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: %s", ErrUnauthorized, res.Reason)
	case http.StatusBadRequest:
		return fmt.Errorf("%w: %s", ErrInvalidRequest, res.Reason)
	default:
		return fmt.Errorf("unexpected broker response %d: %s — %s",
			res.StatusCode, res.Error, res.Reason)
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
