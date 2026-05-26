// Demo of the SDK's primitive — RequestPermission — against the standard
// scopes. Assumes a local interpose daemon is running on 127.0.0.1:7421.
//
// Run with:
//   go run ./examples/basic
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	interpose "github.com/interposehq/interpose-sdk-go"
)

func main() {
	c, err := interpose.New("sdk-demo-basic")
	if err != nil {
		log.Fatalf("new client: %v", err)
	}
	fmt.Println("agent id:", c.AgentID())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	target := "/tmp/sdk-demo-output.txt"
	if err := c.RequestPermission(ctx, "file.write", target); err != nil {
		switch {
		case errors.Is(err, interpose.ErrDenied):
			fmt.Printf("DENIED: %v\n", err)
			os.Exit(1)
		case errors.Is(err, interpose.ErrDaemonUnreachable):
			fmt.Printf("daemon not running? %v\n", err)
			os.Exit(2)
		default:
			fmt.Printf("error: %v\n", err)
			os.Exit(3)
		}
	}
	fmt.Printf("APPROVED — writing to %s\n", target)
	if err := os.WriteFile(target, []byte("hello from interpose-sdk\n"), 0o644); err != nil {
		log.Fatalf("write: %v", err)
	}
	fmt.Println("done.")
}
