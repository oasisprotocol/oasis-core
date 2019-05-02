module github.com/oasislabs/ekiden/go

replace (
	git.schwanenlied.me/yawning/bsaes.git => github.com/yawning/bsaes v0.0.0-20190320102049-26d1add596b6
	git.schwanenlied.me/yawning/dynlib.git => github.com/yawning/dynlib v0.0.0-20181128103533-74a62abb5524
	github.com/tendermint/iavl => github.com/oasislabs/iavl v0.12.0-ekiden2
)

require (
	git.schwanenlied.me/yawning/bsaes.git v0.0.0-20190320102049-26d1add596b6
	git.schwanenlied.me/yawning/dynlib.git v0.0.0-20181128103533-74a62abb5524
	github.com/RoaringBitmap/roaring v0.4.17 // indirect
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/blevesearch/bleve v0.0.0-20190425163828-55bd8a4b302a
	github.com/blevesearch/go-porterstemmer v1.0.2 // indirect
	github.com/blevesearch/segment v0.0.0-20160915185041-762005e7a34f // indirect
	github.com/btcsuite/btcd v0.0.0-20190315201642-aa6e0f35703c // indirect
	github.com/cenkalti/backoff v2.1.1+incompatible
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/couchbase/vellum v0.0.0-20190328134517-462e86d8716b // indirect
	github.com/eapache/channels v1.1.0
	github.com/eapache/queue v1.1.0 // indirect
	github.com/edsrzf/mmap-go v1.0.0 // indirect
	github.com/etcd-io/bbolt v1.3.2
	github.com/fortytw2/leaktest v1.3.0 // indirect
	github.com/go-kit/kit v0.8.0
	github.com/go-logfmt/logfmt v0.4.0 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/golang/protobuf v1.3.1
	github.com/golang/snappy v0.0.1
	github.com/google/gofuzz v0.0.0-20170612174753-24818f796faf // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.0
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jmhodges/levigo v1.0.0 // indirect
	github.com/libp2p/go-libp2p v0.0.3
	github.com/libp2p/go-libp2p-crypto v0.0.1
	github.com/libp2p/go-libp2p-host v0.0.2
	github.com/libp2p/go-libp2p-net v0.0.1
	github.com/libp2p/go-libp2p-peer v0.1.0
	github.com/libp2p/go-libp2p-peerstore v0.0.1
	github.com/libp2p/go-libp2p-protocol v0.0.1
	github.com/multiformats/go-multiaddr v0.0.2
	github.com/oasislabs/deoxysii v0.0.0-20190329164139-cc54819a5e4c
	github.com/oasislabs/go-codec/codec v0.0.0-20190416222655-1c2f272897cf
	github.com/opentracing/opentracing-go v1.1.0
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v0.9.2
	github.com/rcrowley/go-metrics v0.0.0-20181016184325-3113b8401b8a // indirect
	github.com/rs/cors v1.6.0 // indirect
	github.com/seccomp/libseccomp-golang v0.9.0
	github.com/spf13/cobra v0.0.3
	github.com/spf13/pflag v1.0.3
	github.com/spf13/viper v1.3.2
	github.com/steveyen/gtreap v0.0.0-20150807155958-0abe01ef9be2 // indirect
	github.com/stretchr/testify v1.3.0
	github.com/syndtr/goleveldb v1.0.0
	github.com/tendermint/go-amino v0.14.1 // indirect
	github.com/tendermint/iavl v0.12.0
	github.com/tendermint/tendermint v0.31.5
	github.com/uber-go/atomic v1.3.2 // indirect
	github.com/uber/jaeger-client-go v2.16.0+incompatible
	github.com/uber/jaeger-lib v2.0.0+incompatible // indirect
	go.uber.org/atomic v1.3.2 // indirect
	golang.org/x/crypto v0.0.0-20190325154230-a5d413f7728c
	golang.org/x/net v0.0.0-20190328230028-74de082e2cca
	google.golang.org/genproto v0.0.0-20180831171423-11092d34479b // indirect
	google.golang.org/grpc v1.19.1
	gopkg.in/AlecAivazis/survey.v1 v1.8.2
)
