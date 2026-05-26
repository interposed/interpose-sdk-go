.PHONY: test e2e build-interpose tidy clean

# Fast unit tests — no daemon needed.
test:
	go test -count=1 -timeout=30s ./...

# Build the sibling interpose daemon binary. Assumes layout:
#   <parent>/interpose/
#   <parent>/interpose-sdk-go/   <-- you are here
build-interpose:
	cd ../interpose && go build -o bin/interpose ./cmd/interpose

# Full e2e against a real `interpose serve` subprocess. No Lima VM
# required — uses --enforcer noop, so this works on macOS and Linux
# without any kernel-side gating. Tagged tests skipped by `make test`.
e2e: build-interpose
	INTERPOSE_BIN=$(CURDIR)/../interpose/bin/interpose \
	  go test -tags=e2e -count=1 -timeout=60s -v ./...

tidy:
	go mod tidy

clean:
	rm -rf ./bin/
