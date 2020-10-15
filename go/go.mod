module github.com/oasisprotocol/oasis-core/go

replace (
	// Fixes vulnerabilities in etcd v3.3.{10,13} (dependencies via viper).
	// Can be removed once there is a spf13/viper release with updated etcd.
	// https://github.com/spf13/viper/issues/956
	github.com/coreos/etcd => github.com/coreos/etcd v3.3.25+incompatible
	// Updates the version used in spf13/cobra (dependency via tendermint) as
	// there is no release yet with the fix. Remove once an updated release of
	// spf13/cobra exists and tendermint is updated to include it.
	// https://github.com/spf13/cobra/issues/1091
	github.com/gorilla/websocket => github.com/gorilla/websocket v1.4.2

	github.com/tendermint/tendermint => github.com/oasisprotocol/tendermint v0.34.0-rc4-oasis4
	golang.org/x/crypto/curve25519 => github.com/oasisprotocol/ed25519/extra/x25519 v0.0.0-20200819094954-65138ca6ec7c
	golang.org/x/crypto/ed25519 => github.com/oasisprotocol/ed25519 v0.0.0-20200819094954-65138ca6ec7c
)

require (
	github.com/blevesearch/bleve v1.0.12
	github.com/btcsuite/btcutil v1.0.2
	github.com/cenkalti/backoff/v4 v4.1.0
	github.com/cznic/b v0.0.0-20181122101859-a26611c4d92d // indirect
	github.com/cznic/mathutil v0.0.0-20181122101859-297441e03548 // indirect
	github.com/cznic/strutil v0.0.0-20181122101858-275e90344537 // indirect
	github.com/dgraph-io/badger/v2 v2.2007.2
	github.com/eapache/channels v1.1.0
	github.com/fxamacker/cbor/v2 v2.2.1-0.20200820021930-bafca87fa6db
	github.com/go-kit/kit v0.10.0
	github.com/golang/protobuf v1.4.2
	github.com/golang/snappy v0.0.2
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.2
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/go-multierror v1.1.0
	github.com/hashicorp/go-plugin v1.3.0
	github.com/hpcloud/tail v1.0.0
	github.com/libp2p/go-libp2p v0.11.0
	github.com/libp2p/go-libp2p-core v0.6.1
	github.com/libp2p/go-libp2p-pubsub v0.3.6
	github.com/multiformats/go-multiaddr v0.3.1
	github.com/oasisprotocol/deoxysii v0.0.0-20200527154044-851aec403956
	github.com/oasisprotocol/ed25519 v0.0.0-20200819094954-65138ca6ec7c
	github.com/opentracing/opentracing-go v1.2.0
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/common v0.14.0
	github.com/prometheus/procfs v0.2.0
	github.com/remyoudompheng/bigfft v0.0.0-20200410134404-eec4a21b6bb0 // indirect
	github.com/seccomp/libseccomp-golang v0.9.1
	github.com/spf13/cobra v1.1.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/tendermint/tendermint v0.33.6
	github.com/tendermint/tm-db v0.6.2
	github.com/thepudds/fzgo v0.2.2
	github.com/uber/jaeger-client-go v2.25.0+incompatible
	github.com/uber/jaeger-lib v2.2.0+incompatible // indirect
	github.com/whyrusleeping/go-logging v0.0.1
	gitlab.com/yawning/dynlib.git v0.0.0-20200603163025-35fe007b0761
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20200813134508-3edf25e44fcc
	google.golang.org/genproto v0.0.0-20200624020401-64a14ca9d1ad
	google.golang.org/grpc v1.32.0
	google.golang.org/grpc/security/advancedtls v0.0.0-20200902210233-8630cac324bf
	google.golang.org/protobuf v1.25.0
)

go 1.15
