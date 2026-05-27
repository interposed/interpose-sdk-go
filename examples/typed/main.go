// Demo of the typed helpers. Same behavior as examples/basic but with
// scope strings hidden behind RequestFileWrite / RequestExec / etc.
//
// Run with:
//   go run ./examples/typed
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	interpose "github.com/interposed/interpose-sdk-go"
)

func main() {
	c, err := interpose.New("sdk-demo-typed")
	if err != nil {
		log.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Three different gated actions. Each returns nil on approval and
	// ErrDenied if the user (or policy) said no.
	steps := []struct {
		name string
		fn   func() error
	}{
		{
			name: "request to write /tmp/typed-demo.txt",
			fn:   func() error { return c.RequestFileWrite(ctx, "/tmp/typed-demo.txt") },
		},
		{
			name: "request to exec /bin/echo",
			fn:   func() error { return c.RequestExec(ctx, "/bin/echo") },
		},
		{
			name: "request to connect to 1.1.1.1:443",
			fn:   func() error { return c.RequestConnect(ctx, "1.1.1.1", 443) },
		},
	}
	for _, s := range steps {
		fmt.Printf("→ %s ... ", s.name)
		if err := s.fn(); err != nil {
			if errors.Is(err, interpose.ErrDenied) {
				fmt.Printf("DENIED (%v)\n", err)
				continue
			}
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("APPROVED")
	}

	// The exec ask was approved? Run it to confirm.
	out, err := exec.Command("/bin/echo", "hello from typed-demo").CombinedOutput()
	if err != nil {
		log.Fatalf("exec: %v\n%s", err, out)
	}
	fmt.Printf("/bin/echo output: %s", out)
}
