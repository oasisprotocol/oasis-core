module github.com/oasislabs/ekiden/go

replace (
	git.schwanenlied.me/yawning/bsaes.git => github.com/yawning/bsaes v0.0.0-20190320102049-26d1add596b6
	git.schwanenlied.me/yawning/dynlib.git => github.com/yawning/dynlib v0.0.0-20181128103533-74a62abb5524
	github.com/tendermint/iavl => github.com/oasislabs/iavl v0.12.0-ekiden2
)

require (
	git.schwanenlied.me/yawning/dynlib.git v0.0.0-20181128103533-74a62abb5524
	github.com/Netflix/go-expect v0.0.0-20180928190340-9d1f4485533b // indirect
	github.com/RoaringBitmap/roaring v0.4.18 // indirect
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/blevesearch/bleve v0.7.1-0.20190531184658-92623347bffc
	github.com/blevesearch/blevex v0.0.0-20180227211930-4b158bb555a3 // indirect
	github.com/blevesearch/go-porterstemmer v1.0.2 // indirect
	github.com/blevesearch/segment v0.0.0-20160915185041-762005e7a34f // indirect
	github.com/btcsuite/btcd v0.0.0-20190614013741-962a206e94e9 // indirect
	github.com/cenkalti/backoff v2.1.1+incompatible
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/couchbase/vellum v0.0.0-20190610201045-ec7b775d247f // indirect
	github.com/cznic/b v0.0.0-20181122101859-a26611c4d92d // indirect
	github.com/cznic/mathutil v0.0.0-20181122101859-297441e03548 // indirect
	github.com/cznic/strutil v0.0.0-20181122101858-275e90344537 // indirect
	github.com/dgraph-io/badger/v2 v2.0.0-rc.2.0.20190624233936-91ce6876dbdc
	github.com/eapache/channels v1.1.0
	github.com/eapache/queue v1.1.0 // indirect
	github.com/edsrzf/mmap-go v1.0.0 // indirect
	github.com/etcd-io/bbolt v1.3.3
	github.com/facebookgo/ensure v0.0.0-20160127193407-b4ab57deab51 // indirect
	github.com/facebookgo/stack v0.0.0-20160209184415-751773369052 // indirect
	github.com/facebookgo/subset v0.0.0-20150612182917-8dac2c3c4870 // indirect
	github.com/fortytw2/leaktest v1.3.0 // indirect
	github.com/glycerine/goconvey v0.0.0-20190410193231-58a59202ab31 // indirect
	github.com/go-kit/kit v0.8.0
	github.com/go-logfmt/logfmt v0.4.0 // indirect
	github.com/golang/protobuf v1.3.1
	github.com/golang/snappy v0.0.1
	github.com/google/gofuzz v1.0.0 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20190430165422-3e4dfb77656c // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.0
	github.com/hinshun/vt10x v0.0.0-20180809195222-d55458df857c // indirect
	github.com/jmhodges/levigo v1.0.0 // indirect
	github.com/kr/pty v1.1.5 // indirect
	github.com/libp2p/go-libp2p v0.1.1
	github.com/libp2p/go-libp2p-core v0.0.3
	github.com/libp2p/go-libp2p-crypto v0.1.0
	github.com/libp2p/go-libp2p-host v0.1.0
	github.com/libp2p/go-libp2p-net v0.1.0
	github.com/libp2p/go-libp2p-peer v0.2.0
	github.com/libp2p/go-libp2p-peerstore v0.1.0
	github.com/libp2p/go-libp2p-protocol v0.1.0
	github.com/libp2p/go-msgio v0.0.3 // indirect
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/mattn/go-colorable v0.1.2 // indirect
	github.com/multiformats/go-multiaddr v0.0.4
	github.com/multiformats/go-multihash v0.0.6 // indirect
	github.com/oasislabs/deoxysii v0.0.0-20190610083944-a3e81dcb2dde
	github.com/oasislabs/go-codec v0.0.0-20190612092255-497cc071f728
	github.com/opentracing/opentracing-go v1.1.0
	github.com/pelletier/go-toml v1.4.0 // indirect
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v0.9.4
	github.com/rcrowley/go-metrics v0.0.0-20181016184325-3113b8401b8a // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20190512091148-babf20351dd7 // indirect
	github.com/rs/cors v1.6.0 // indirect
	github.com/seccomp/libseccomp-golang v0.9.1
	github.com/smartystreets/assertions v1.0.0 // indirect
	github.com/smartystreets/goconvey v0.0.0-20190330032615-68dc04aab96a // indirect
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/cobra v0.0.5
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.3
	github.com/spf13/viper v1.4.0
	github.com/steveyen/gtreap v0.0.0-20150807155958-0abe01ef9be2 // indirect
	github.com/stretchr/testify v1.3.0
	github.com/syndtr/goleveldb v1.0.1-0.20190318030020-c3a204f8e965
	github.com/tecbot/gorocksdb v0.0.0-20190519120508-025c3cf4ffb4 // indirect
	github.com/tendermint/go-amino v0.15.0 // indirect
	github.com/tendermint/iavl v0.12.2
	github.com/tendermint/tendermint v0.31.7
	github.com/uber-go/atomic v1.4.0 // indirect
	github.com/uber/jaeger-client-go v2.16.0+incompatible
	github.com/uber/jaeger-lib v2.0.0+incompatible // indirect
	github.com/whyrusleeping/go-logging v0.0.0-20170515211332-0457bb6b88fc
	go.etcd.io/bbolt v1.3.3 // indirect
	golang.org/x/crypto v0.0.0-20190611184440-5c40567a22f8
	golang.org/x/net v0.0.0-20190613194153-d28f0bde5980
	golang.org/x/sys v0.0.0-20190614084037-d442b75600c5 // indirect
	golang.org/x/text v0.3.2 // indirect
	google.golang.org/appengine v1.4.0 // indirect
	google.golang.org/genproto v0.0.0-20190611190212-a7e196e89fd3 // indirect
	google.golang.org/grpc v1.21.1
	gopkg.in/AlecAivazis/survey.v1 v1.8.5
)
