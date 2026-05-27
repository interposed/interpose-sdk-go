//go:build e2e

package interpose_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	interpose "github.com/interposed/interpose-sdk-go"
)

// TestE2E_CooperativePath exercises the SDK end-to-end against a real
// `interpose serve` daemon spawned as a subprocess. No Lima VM, no kernel
// enforcer — pure cooperative path against the noop enforcer. Runs on
// macOS or Linux.
//
// Verifies:
//   - signed aa-agent+jwt is accepted by the broker
//   - auto-allow / auto-deny / require-auth policy actions all flow back
//     to the SDK with the correct typed result
//   - typed helpers map to the broker scope strings consistently
//
// Run with:
//
//	make e2e
//
// or:
//
//	(cd ../interpose && go build -o bin/interpose ./cmd/interpose) && \
//	  INTERPOSE_BIN=$PWD/../interpose/bin/interpose \
//	  go test -tags=e2e -count=1 -timeout=60s ./...
//
// HOME is redirected to a tempdir so the daemon's audit log + signing key
// land outside the developer's real ~/Library/Application Support/.
func TestE2E_CooperativePath(t *testing.T) {
	d := startDaemon(t)
	home := os.Getenv("HOME") // startDaemon redirected this to t.TempDir()

	c, err := interpose.New("sdk-e2e", interpose.WithAddr(d.addr))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Cases align with the default policy rules in cmd/interpose/serve.go:
	//   file.write /tmp/**        → auto-allow         (no prompt)
	//   file.write /etc/**        → auto-deny          (403)
	//   file.write ~/.ssh/**      → require-high       (testauto approves)
	//   file.write ~/Documents/** → auto-allow         (no prompt)
	//   default                   → require-medium     (testauto approves)
	cases := []struct {
		name    string
		run     func() error
		wantErr error // nil = expect approval
	}{
		{
			name: "auto_allow_tmp_write",
			run:  func() error { return c.RequestFileWrite(ctx, "/tmp/sdk-e2e-allow") },
		},
		{
			name: "auto_allow_documents_write",
			run: func() error {
				return c.RequestFileWrite(ctx, filepath.Join(home, "Documents/sdk-e2e-allow"))
			},
		},
		{
			name:    "auto_deny_etc_write",
			run:     func() error { return c.RequestFileWrite(ctx, "/etc/sdk-e2e-deny") },
			wantErr: interpose.ErrDenied,
		},
		{
			name: "require_high_ssh_testauto_approves",
			run: func() error {
				return c.RequestFileWrite(ctx, filepath.Join(home, ".ssh/sdk-e2e-key"))
			},
		},
		{
			name: "require_medium_exec_testauto_approves",
			run:  func() error { return c.RequestExec(ctx, "/bin/echo") },
		},
		{
			name: "require_medium_connect_testauto_approves",
			run:  func() error { return c.RequestConnect(ctx, "1.1.1.1", 443) },
		},
		{
			name: "require_medium_file_read_testauto_approves",
			run:  func() error { return c.RequestFileRead(ctx, "/tmp/sdk-e2e-read") },
		},
		{
			name: "primitive_custom_scope_testauto_approves",
			run:  func() error { return c.RequestPermission(ctx, "custom.scope", "anything") },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if tc.wantErr == nil {
				if err != nil {
					d.dumpLog(t)
					t.Fatalf("expected approval, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				d.dumpLog(t)
				t.Fatalf("expected errors.Is(..., %v), got %v", tc.wantErr, err)
			}
		})
	}
}

// TestE2E_DaemonRestart_AgentKeysAreEphemeral verifies that a fresh
// Client created after a daemon restart still works — i.e. there's no
// stale broker-side state binding the agent's old keypair. Confirms the
// AAuth "instance-scoped identity" property holds end-to-end.
func TestE2E_DaemonRestart_AgentKeysAreEphemeral(t *testing.T) {
	d := startDaemon(t)

	c1, err := interpose.New("sdk-e2e", interpose.WithAddr(d.addr))
	if err != nil {
		t.Fatalf("New (round 1): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c1.RequestFileWrite(ctx, "/tmp/sdk-e2e-r1"); err != nil {
		t.Fatalf("round 1: %v", err)
	}

	// Restart the daemon — broker signing key rotates, audit log
	// chain may or may not continue (depends on whether HOME's audit
	// log persists; in the t.TempDir scope, yes it does for the
	// lifetime of THIS test, but it's a fresh broker process either
	// way).
	d.stop()
	d = startDaemon(t)
	c2, err := interpose.New("sdk-e2e-take2", interpose.WithAddr(d.addr))
	if err != nil {
		t.Fatalf("New (round 2): %v", err)
	}
	if err := c2.RequestFileWrite(ctx, "/tmp/sdk-e2e-r2"); err != nil {
		t.Fatalf("round 2 after daemon restart: %v", err)
	}
}

// ----------------------------------------------------------------------------
// daemon subprocess helpers
// ----------------------------------------------------------------------------

type daemonProc struct {
	cmd     *exec.Cmd
	addr    string
	logPath string
}

func startDaemon(t *testing.T) *daemonProc {
	t.Helper()

	binary := os.Getenv("INTERPOSE_BIN")
	if binary == "" {
		abs, _ := filepath.Abs("../interpose/bin/interpose")
		binary = abs
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("interpose binary not found at %s\n\nset INTERPOSE_BIN, or build with:\n  (cd ../interpose && go build -o bin/interpose ./cmd/interpose)\n\nor run via the Makefile:\n  make e2e", binary)
	}

	// Redirect HOME so the daemon's audit log + signing key (which it
	// drops in os.UserConfigDir) don't pollute the developer's machine.
	// We also need this for the ssh-glob policy rule to resolve to a
	// path under our control.
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("INTERPOSE_INSECURE_TESTING", "1")
	// macOS UserConfigDir = $HOME/Library/Application Support; pre-create
	// so the daemon doesn't have to. (mkdir is idempotent inside.)
	_ = os.MkdirAll(filepath.Join(tempHome, "Library", "Application Support"), 0o700)

	brokerPort := freePort(t)
	authPort := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", brokerPort)
	authAddr := fmt.Sprintf("127.0.0.1:%d", authPort)

	logFile, err := os.CreateTemp("", "interpose-e2e-*.log")
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}

	cmd := exec.Command(binary, "serve",
		"--enforcer", "noop",
		"--insecure-test-auth",
		"--addr", addr,
		"--auth-addr", authAddr,
	)
	cmd.Env = os.Environ() // inherits t.Setenv values
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("start daemon: %v", err)
	}

	d := &daemonProc{cmd: cmd, addr: addr, logPath: logFile.Name()}
	logFile.Close() // daemon has the fd; we'll re-open for reading on dumpLog
	t.Cleanup(d.stop)

	// Wait for /v0/health to respond 200.
	deadline := time.Now().Add(10 * time.Second)
	healthURL := "http://" + addr + "/v0/health"
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return d
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	d.dumpLog(t)
	t.Fatalf("daemon at %s did not respond healthy within 10s", addr)
	return nil
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func (d *daemonProc) stop() {
	if d.cmd == nil || d.cmd.Process == nil {
		return
	}
	_ = d.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_ = d.cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = d.cmd.Process.Kill()
		<-done
	}
	d.cmd = nil
}

func (d *daemonProc) dumpLog(t *testing.T) {
	t.Helper()
	if d.logPath == "" {
		return
	}
	b, err := os.ReadFile(d.logPath)
	if err != nil {
		t.Logf("(could not read daemon log %s: %v)", d.logPath, err)
		return
	}
	t.Logf("--- daemon log (%s) ---\n%s", d.logPath, b)
}
