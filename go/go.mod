module github.com/oasisprotocol/oasis-core/go

replace (
	// Fixes vulnerabilities in etcd v3.3.{10,13} (dependencies via viper).
	// Can be removed once there is a spf13/viper release with updated
	// etcd and other dependencies using viper are updated.
	// https://github.com/spf13/viper/issues/956
	github.com/coreos/etcd => github.com/coreos/etcd v3.3.25+incompatible
	// Updates the version used by badgerdb, because some of the Go
	// module caches apparently have a messed up copy that causes
	// build failures.
	// https://github.com/google/flatbuffers/issues/6466
	github.com/google/flatbuffers => github.com/google/flatbuffers v1.12.1

	github.com/tendermint/tendermint => github.com/oasisprotocol/tendermint v0.34.9-oasis2

	golang.org/x/crypto/curve25519 => github.com/oasisprotocol/curve25519-voi/primitives/x25519 v0.0.0-20210505121811-294cf0fbfb43
	golang.org/x/crypto/ed25519 => github.com/oasisprotocol/curve25519-voi/primitives/ed25519 v0.0.0-20210505121811-294cf0fbfb43
)

require (
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/cenkalti/backoff/v4 v4.1.1
	github.com/dgraph-io/badger/v2 v2.2007.2
	github.com/dgraph-io/badger/v3 v3.2103.2
	github.com/eapache/channels v1.1.0
	github.com/facebookgo/ensure v0.0.0-20200202191622-63f1cf65ac4c // indirect
	github.com/facebookgo/subset v0.0.0-20200203212716-c811ad88dec4 // indirect
	github.com/fxamacker/cbor/v2 v2.2.1-0.20200820021930-bafca87fa6db
	github.com/go-kit/log v0.2.0
	github.com/golang/protobuf v1.5.2
	github.com/golang/snappy v0.0.4
	github.com/google/btree v1.0.1
	github.com/hashicorp/go-hclog v0.16.2
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-plugin v1.4.2
	github.com/hpcloud/tail v1.0.0
	github.com/ianbruene/go-difflib v1.2.0
	github.com/libp2p/go-libp2p v0.15.1
	github.com/libp2p/go-libp2p-core v0.9.0
	github.com/libp2p/go-libp2p-pubsub v0.5.6
	github.com/multiformats/go-multiaddr v0.4.1
	github.com/oasisprotocol/curve25519-voi v0.0.0-20210505121811-294cf0fbfb43
	github.com/oasisprotocol/deoxysii v0.0.0-20200527154044-851aec403956
	github.com/powerman/rpc-codec v1.2.2
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/common v0.31.1
	github.com/prometheus/procfs v0.7.3
	github.com/seccomp/libseccomp-golang v0.9.1
	github.com/spf13/cobra v1.2.1
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.9.0
	github.com/stretchr/testify v1.7.0
	github.com/tendermint/tendermint v0.34.9
	github.com/tendermint/tm-db v0.6.4
	github.com/thepudds/fzgo v0.2.2
	github.com/tyler-smith/go-bip39 v1.1.0
	github.com/whyrusleeping/go-logging v0.0.1
	gitlab.com/yawning/dynlib.git v0.0.0-20210614104444-f6a90d03b144
	go.dedis.ch/kyber/v3 v3.0.13
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	golang.org/x/net v0.0.0-20210813160813-60bc85c4be6d
	google.golang.org/genproto v0.0.0-20210828152312-66f60bf46e71
	google.golang.org/grpc v1.41.0
	google.golang.org/grpc/security/advancedtls v0.0.0-20200902210233-8630cac324bf
	google.golang.org/protobuf v1.27.1
)

go 1.16
