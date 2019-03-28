module github.com/oasislabs/ekiden/go

replace (
	git.schwanenlied.me/yawning/bsaes.git => github.com/yawning/bsaes v0.0.0-20190320102049-26d1add596b6
	git.schwanenlied.me/yawning/dynlib.git => github.com/yawning/dynlib v0.0.0-20181128103533-74a62abb5524
	github.com/ipfs/go-cid => github.com/ipfs/go-cid v0.0.0-00000000000000-6e296c5c49ad
	github.com/ipfs/go-ipfs-util => github.com/ipfs/go-ipfs-util v0.0.0-00000000000000-10d786c5ed85
	github.com/ipfs/go-log => github.com/ipfs/go-log v0.0.0-00000000000000-14e95105cbaf
	github.com/libp2p/go-addr-util => github.com/libp2p/go-addr-util v0.0.0-00000000000000-94b4c8b41eba
	github.com/libp2p/go-buffer-pool => github.com/libp2p/go-buffer-pool v0.0.0-00000000000000-058210c5a0d0
	github.com/libp2p/go-conn-security => github.com/libp2p/go-conn-security v0.0.0-00000000000000-b7192598fc6d
	github.com/libp2p/go-conn-security-multistream => github.com/libp2p/go-conn-security-multistream v0.0.0-00000000000000-578125a681ee
	github.com/libp2p/go-flow-metrics => github.com/libp2p/go-flow-metrics v0.0.0-00000000000000-cc546389dcf0
	github.com/libp2p/go-libp2p => github.com/libp2p/go-libp2p v0.0.0-00000000000000-1a0c9bc9f4ef
	github.com/libp2p/go-libp2p-blankhost => github.com/libp2p/go-libp2p-blankhost v0.0.0-00000000000000-4fc7b2545c20
	github.com/libp2p/go-libp2p-circuit => github.com/libp2p/go-libp2p-circuit v0.0.0-00000000000000-16eb677aaa62
	github.com/libp2p/go-libp2p-crypto => github.com/libp2p/go-libp2p-crypto v0.0.0-00000000000000-a3075f70fa87
	github.com/libp2p/go-libp2p-host => github.com/libp2p/go-libp2p-host v0.0.0-00000000000000-5e19768b7bf3
	github.com/libp2p/go-libp2p-interface-connmgr => github.com/libp2p/go-libp2p-interface-connmgr v0.0.0-00000000000000-61a030e46d8f
	github.com/libp2p/go-libp2p-interface-pnet => github.com/libp2p/go-libp2p-interface-pnet v0.0.0-00000000000000-3eda0a328422
	github.com/libp2p/go-libp2p-loggables => github.com/libp2p/go-libp2p-loggables v0.0.0-00000000000000-2edffda90e41
	github.com/libp2p/go-libp2p-metrics => github.com/libp2p/go-libp2p-metrics v0.0.0-00000000000000-20c0e3fed14d
	github.com/libp2p/go-libp2p-nat => github.com/libp2p/go-libp2p-nat v0.0.0-00000000000000-b82aac8589e1
	github.com/libp2p/go-libp2p-net => github.com/libp2p/go-libp2p-net v0.0.0-00000000000000-22c96766db92
	github.com/libp2p/go-libp2p-peerstore => github.com/libp2p/go-libp2p-peerstore v0.0.0-00000000000000-6295e61c9fd2
	github.com/libp2p/go-libp2p-protocol => github.com/libp2p/go-libp2p-protocol v0.0.0-00000000000000-e34f0d7468b3
	github.com/libp2p/go-libp2p-routing => github.com/libp2p/go-libp2p-routing v0.0.0-00000000000000-c568217bd16d
	github.com/libp2p/go-libp2p-secio => github.com/libp2p/go-libp2p-secio v0.0.0-00000000000000-8f95e95b9fed
	github.com/libp2p/go-libp2p-swarm => github.com/libp2p/go-libp2p-swarm v0.0.0-00000000000000-839f88f8de4d
	github.com/libp2p/go-libp2p-transport => github.com/libp2p/go-libp2p-transport v0.0.0-00000000000000-e6d021be15cb
	github.com/libp2p/go-libp2p-transport-upgrader => github.com/libp2p/go-libp2p-transport-upgrader v0.0.0-00000000000000-8dde02b5e753
	github.com/libp2p/go-maddr-filter => github.com/libp2p/go-maddr-filter v0.0.0-00000000000000-7f7ca1e79c45
	github.com/libp2p/go-mplex => github.com/libp2p/go-mplex v0.0.0-00000000000000-1386e7e22616
	github.com/libp2p/go-msgio => github.com/libp2p/go-msgio v0.0.0-00000000000000-031a413e6612
	github.com/libp2p/go-reuseport => github.com/libp2p/go-reuseport v0.0.0-00000000000000-b3fd01f43ca5
	github.com/libp2p/go-reuseport-transport => github.com/libp2p/go-reuseport-transport v0.0.0-00000000000000-98b2c72d3253
	github.com/libp2p/go-sockaddr => github.com/libp2p/go-sockaddr v0.0.0-00000000000000-5c3ac7e71ec1
	github.com/libp2p/go-stream-muxer => github.com/libp2p/go-stream-muxer v0.0.0-00000000000000-2ba231669cdd
	github.com/libp2p/go-tcp-transport => github.com/libp2p/go-tcp-transport v0.0.0-00000000000000-7e41190ec068
	github.com/libp2p/go-testutil => github.com/libp2p/go-testutil v0.0.0-20181024164553-58107e702ea7
	github.com/libp2p/go-ws-transport => github.com/libp2p/go-ws-transport v0.0.0-00000000000000-246ec4b8bd9a
	github.com/multiformats/go-multiaddr => github.com/multiformats/go-multiaddr v0.0.0-00000000000000-8c3eb5dc1c12
	github.com/multiformats/go-multiaddr-dns => github.com/multiformats/go-multiaddr-dns v0.0.0-00000000000000-317a9bc842d4
	github.com/multiformats/go-multiaddr-net => github.com/multiformats/go-multiaddr-net v0.0.0-00000000000000-c75d1cac17a0
	github.com/multiformats/go-multibase => github.com/multiformats/go-multibase v0.0.0-00000000000000-bb91b53e5695
	github.com/multiformats/go-multihash => github.com/multiformats/go-multihash v0.0.0-00000000000000-8be2a682ab9f
	github.com/multiformats/go-multistream => github.com/multiformats/go-multistream v0.0.0-00000000000000-0e509f6b999d
	github.com/tendermint/iavl => github.com/oasislabs/iavl v0.12.0-ekiden2
)

require (
	git.schwanenlied.me/yawning/bsaes.git v0.0.0-20190320102049-26d1add596b6
	git.schwanenlied.me/yawning/dynlib.git v0.0.0-20181128103533-74a62abb5524
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/Netflix/go-expect v0.0.0-20180928190340-9d1f4485533b // indirect
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/btcsuite/btcd v0.0.0-20190213025234-306aecffea32 // indirect
	github.com/cenkalti/backoff v2.1.1+incompatible
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/eapache/channels v1.1.0
	github.com/eapache/queue v1.1.0 // indirect
	github.com/ethereum/go-ethereum v1.8.22 // indirect
	github.com/fd/go-nat v1.0.0 // indirect
	github.com/fortytw2/leaktest v1.3.0 // indirect
	github.com/go-kit/kit v0.8.0
	github.com/go-logfmt/logfmt v0.4.0 // indirect
	github.com/golang/protobuf v1.2.0
	github.com/golang/snappy v0.0.0-20180518054509-2e65f85255db
	github.com/google/gofuzz v0.0.0-20170612174753-24818f796faf // indirect
	github.com/google/uuid v1.1.0 // indirect
	github.com/gorilla/websocket v1.4.0 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.0
	github.com/hinshun/vt10x v0.0.0-20180809195222-d55458df857c // indirect
	github.com/huin/goupnp v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/ipfs/go-cid v0.9.0 // indirect
	github.com/ipfs/go-ipfs-util v1.2.8 // indirect
	github.com/jackpal/gateway v1.0.5 // indirect
	github.com/jbenet/go-cienv v0.0.0-20150120210510-1bb1476777ec // indirect
	github.com/jbenet/go-randbuf v0.0.0-20160322125720-674640a50e6a // indirect
	github.com/jbenet/go-temp-err-catcher v0.0.0-20150120210811-aac704a3f4f2 // indirect
	github.com/jbenet/goprocess v0.0.0-20160826012719-b497e2f366b8 // indirect
	github.com/jmhodges/levigo v0.0.0-20161115193449-c42d9e0ca023 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/kr/pty v1.1.3 // indirect
	github.com/libp2p/go-addr-util v2.0.7+incompatible // indirect
	github.com/libp2p/go-buffer-pool v0.1.3 // indirect
	github.com/libp2p/go-conn-security v0.1.15 // indirect
	github.com/libp2p/go-conn-security-multistream v0.1.15 // indirect
	github.com/libp2p/go-flow-metrics v0.2.0 // indirect
	github.com/libp2p/go-libp2p v6.0.29+incompatible
	github.com/libp2p/go-libp2p-autonat v0.0.0-20190207233022-494f7fce997b // indirect
	github.com/libp2p/go-libp2p-blankhost v0.3.15 // indirect
	github.com/libp2p/go-libp2p-circuit v2.3.2+incompatible // indirect
	github.com/libp2p/go-libp2p-crypto v2.0.5+incompatible
	github.com/libp2p/go-libp2p-discovery v0.0.0-20190212175932-d4858e0322b6 // indirect
	github.com/libp2p/go-libp2p-host v3.0.15+incompatible
	github.com/libp2p/go-libp2p-interface-connmgr v0.0.21 // indirect
	github.com/libp2p/go-libp2p-interface-pnet v3.0.0+incompatible // indirect
	github.com/libp2p/go-libp2p-loggables v1.1.24 // indirect
	github.com/libp2p/go-libp2p-metrics v2.1.7+incompatible // indirect
	github.com/libp2p/go-libp2p-nat v0.8.8 // indirect
	github.com/libp2p/go-libp2p-net v3.0.15+incompatible
	github.com/libp2p/go-libp2p-peer v2.4.1-0.20181212195732-f5c52cebf45b+incompatible
	github.com/libp2p/go-libp2p-peerstore v2.0.6+incompatible
	github.com/libp2p/go-libp2p-protocol v1.0.0
	github.com/libp2p/go-libp2p-routing v2.7.1+incompatible // indirect
	github.com/libp2p/go-libp2p-secio v2.0.17+incompatible // indirect
	github.com/libp2p/go-libp2p-swarm v3.0.22+incompatible // indirect
	github.com/libp2p/go-libp2p-transport v3.0.15+incompatible // indirect
	github.com/libp2p/go-libp2p-transport-upgrader v0.1.16 // indirect
	github.com/libp2p/go-maddr-filter v1.1.10 // indirect
	github.com/libp2p/go-mplex v0.2.30 // indirect
	github.com/libp2p/go-msgio v0.0.6 // indirect
	github.com/libp2p/go-reuseport-transport v0.2.0 // indirect
	github.com/libp2p/go-stream-muxer v3.0.1+incompatible // indirect
	github.com/libp2p/go-tcp-transport v2.0.16+incompatible // indirect
	github.com/libp2p/go-testutil v1.2.10 // indirect
	github.com/libp2p/go-ws-transport v2.0.15+incompatible // indirect
	github.com/mattn/go-colorable v0.1.0 // indirect
	github.com/minio/sha256-simd v0.0.0-20190131020904-2d45a736cd16 // indirect
	github.com/multiformats/go-multiaddr v1.4.0
	github.com/multiformats/go-multibase v0.3.0 // indirect
	github.com/multiformats/go-multistream v0.3.9 // indirect
	github.com/oasislabs/deoxysii v0.0.0-20190327111415-34b555e1c03c
	github.com/opentracing/opentracing-go v1.0.2
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v0.9.2
	github.com/prometheus/client_model v0.0.0-20190129233127-fd36f4220a90 // indirect
	github.com/prometheus/common v0.2.0 // indirect
	github.com/prometheus/procfs v0.0.0-20190209105433-f8d8b3f739bd // indirect
	github.com/rcrowley/go-metrics v0.0.0-20181016184325-3113b8401b8a // indirect
	github.com/rs/cors v1.6.0 // indirect
	github.com/seccomp/libseccomp-golang v0.9.0
	github.com/spf13/afero v1.2.1 // indirect
	github.com/spf13/cobra v0.0.3
	github.com/spf13/pflag v1.0.3
	github.com/spf13/viper v1.3.1
	github.com/stretchr/testify v1.3.0
	github.com/syndtr/goleveldb v0.0.0-20190203031304-2f17a3356c66
	github.com/tendermint/go-amino v0.14.1 // indirect
	github.com/tendermint/iavl v0.12.0
	github.com/tendermint/tendermint v0.30.1
	github.com/uber-go/atomic v1.3.2 // indirect
	github.com/uber/jaeger-client-go v2.15.1-0.20190116124224-6733ee486c78+incompatible
	github.com/uber/jaeger-lib v2.0.0+incompatible // indirect
	github.com/ugorji/go/codec v0.0.0-20190204201341-e444a5086c43
	github.com/whyrusleeping/base32 v0.0.0-20170828182744-c30ac30633cc // indirect
	github.com/whyrusleeping/go-notifier v0.0.0-20170827234753-097c5d47330f // indirect
	github.com/whyrusleeping/go-smux-multiplex v3.0.16+incompatible // indirect
	github.com/whyrusleeping/go-smux-multistream v2.0.2+incompatible // indirect
	github.com/whyrusleeping/go-smux-yamux v2.0.8+incompatible // indirect
	github.com/whyrusleeping/mafmt v1.2.8 // indirect
	github.com/whyrusleeping/multiaddr-filter v0.0.0-20160516205228-e903e4adabd7 // indirect
	github.com/whyrusleeping/yamux v1.1.5 // indirect
	go.etcd.io/bbolt v1.3.2
	go.uber.org/atomic v1.3.2 // indirect
	golang.org/x/crypto v0.0.0-20190211182817-74369b46fc67
	golang.org/x/net v0.0.0-20190213061140-3a22650c66bd
	golang.org/x/sys v0.0.0-20190209173611-3b5209105503 // indirect
	golang.org/x/text v0.3.1-0.20180807135948-17ff2d5776d2 // indirect
	google.golang.org/genproto v0.0.0-20190201180003-4b09977fb922 // indirect
	google.golang.org/grpc v1.18.0
	gopkg.in/AlecAivazis/survey.v1 v1.8.2
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)
