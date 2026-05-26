package interpose

import "errors"

// Errors returned by the SDK. Use errors.Is to match.
var (
	// ErrDenied means the broker refused the request — either policy
	// auto-deny, the user pressed deny on the auth prompt, or the user
	// didn't respond before the broker's prompt timeout.
	ErrDenied = errors.New("interpose: action denied")

	// ErrDaemonUnreachable means the SDK couldn't reach the broker over
	// HTTP. Common causes: daemon not running, wrong INTERPOSE_ADDR,
	// network namespace mismatch.
	ErrDaemonUnreachable = errors.New("interpose: daemon unreachable")

	// ErrUnauthorized means the broker rejected the agent token. Usually
	// indicates a clock-skew issue (signed token's exp is in the past) or
	// a broker that doesn't recognize this AAuth protocol version.
	ErrUnauthorized = errors.New("interpose: unauthorized")

	// ErrInvalidRequest means the broker rejected the request shape (e.g.
	// missing scope or target). Programmer error — fix the call site.
	ErrInvalidRequest = errors.New("interpose: invalid request")
)
