module github.com/oasisprotocol/oasis-core/go

replace (
	// Updates the version used in spf13/cobra (dependency via tendermint) as
	// there is no release yet with the fix. Remove once an updated release of
	// spf13/cobra exists and tendermint is updated to include it.
	// https://github.com/spf13/cobra/issues/1091
	github.com/gorilla/websocket => github.com/gorilla/websocket v1.4.2

	github.com/tendermint/tendermint => github.com/oasisprotocol/tendermint v0.33.4-oasis2
	golang.org/x/crypto/curve25519 => github.com/oasisprotocol/ed25519/extra/x25519 v0.0.0-20200528083105-55566edd6df0
	golang.org/x/crypto/ed25519 => github.com/oasisprotocol/ed25519 v0.0.0-20200528083105-55566edd6df0
)

require (
	github.com/blevesearch/bleve v1.0.9
	github.com/btcsuite/btcutil v1.0.2
	github.com/cenkalti/backoff/v4 v4.0.0
	github.com/cznic/b v0.0.0-20181122101859-a26611c4d92d // indirect
	github.com/cznic/mathutil v0.0.0-20181122101859-297441e03548 // indirect
	github.com/cznic/strutil v0.0.0-20181122101858-275e90344537 // indirect
	github.com/davidlazar/go-crypto v0.0.0-20200604182044-b73af7476f6c // indirect
	github.com/dgraph-io/badger/v2 v2.0.3
	github.com/eapache/channels v1.1.0
	github.com/fxamacker/cbor/v2 v2.2.1-0.20200526031912-58b82b5bfc05
	github.com/go-kit/kit v0.10.0
	github.com/golang/protobuf v1.4.0
	github.com/golang/snappy v0.0.1
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.1-0.20190118093823-f849b5445de4
	github.com/hpcloud/tail v1.0.0
	github.com/ipfs/go-log/v2 v2.1.1 // indirect
	github.com/libp2p/go-libp2p v0.9.6
	github.com/libp2p/go-libp2p-core v0.6.0
	github.com/libp2p/go-libp2p-pubsub v0.3.1
	github.com/libp2p/go-libp2p-swarm v0.2.7 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-multiaddr v0.2.2
	github.com/multiformats/go-multiaddr-net v0.1.5
	github.com/oasisprotocol/deoxysii v0.0.0-20200527154044-851aec403956
	github.com/oasisprotocol/ed25519 v0.0.0-20200528083105-55566edd6df0
	github.com/opentracing/opentracing-go v1.1.0
	github.com/prometheus/client_golang v1.5.1
	github.com/prometheus/common v0.9.1
	github.com/prometheus/procfs v0.0.8
	github.com/remyoudompheng/bigfft v0.0.0-20190512091148-babf20351dd7 // indirect
	github.com/seccomp/libseccomp-golang v0.9.1
	github.com/smartystreets/assertions v1.0.0 // indirect
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.6.1
	github.com/tendermint/go-amino v0.15.0
	github.com/tendermint/tendermint v0.33.4
	github.com/tendermint/tm-db v0.5.1
	github.com/thepudds/fzgo v0.2.2
	github.com/uber-go/atomic v1.4.0 // indirect
	github.com/uber/jaeger-client-go v2.16.0+incompatible
	github.com/uber/jaeger-lib v2.0.0+incompatible // indirect
	github.com/whyrusleeping/go-logging v0.0.1
	github.com/zondax/ledger-oasis-go v0.3.0
	gitlab.com/yawning/dynlib.git v0.0.0-20200603163025-35fe007b0761
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9
	golang.org/x/net v0.0.0-20200602114024-627f9648deb9
	golang.org/x/sys v0.0.0-20200610111108-226ff32320da // indirect
	google.golang.org/genproto v0.0.0-20191108220845-16a3f7862a1a
	google.golang.org/grpc v1.29.1
	google.golang.org/grpc/security/advancedtls v0.0.0-20200504170109-c8482678eb49
	google.golang.org/protobuf v1.23.0
)

go 1.14
