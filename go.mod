module github.com/interposed/interpose-sdk-go

go 1.25.0

require github.com/interposed/interpose v0.8.2

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/dunglas/httpsfv v1.0.2 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.0.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.6 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.1 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/jwx/v2 v2.1.2 // indirect
	github.com/lestrrat-go/jwx/v3 v3.0.12 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	github.com/yaronf/httpsign v0.5.1 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

// The SDK is public but its interposed/interpose dependency is still
// private — pkg/aauth/* in interpose will be relocated into this SDK
// so it builds for external consumers. Until then, this replace
// directive lets contributors build the SDK locally when both repos
// are cloned as siblings (see README.md).
replace github.com/interposed/interpose => ../interpose
