module github.com/oasislabs/ekiden/go

replace (
	github.com/tendermint/iavl => github.com/oasislabs/iavl v0.11.0-ekiden3
	github.com/tendermint/tendermint => github.com/oasislabs/tendermint v0.25.0-ekiden1
)

require (
	git.schwanenlied.me/yawning/bsaes.git v0.0.0-20180720073208-c0276d75487e
	github.com/beorn7/perks v0.0.0-20180321164747-3a771d992973 // indirect
	github.com/btcsuite/btcd v0.0.0-20180903232927-cff30e1d23fc // indirect
	github.com/cockroachdb/cockroach-go v0.0.0-20181001143604-e0a95dfd547c
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/eapache/channels v1.1.0
	github.com/eapache/queue v1.1.0 // indirect
	github.com/ebuchman/fail-test v0.0.0-20170303061230-95f809107225 // indirect
	github.com/fsnotify/fsnotify v1.4.7 // indirect
	github.com/go-kit/kit v0.6.0
	github.com/go-logfmt/logfmt v0.3.0 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/gogo/protobuf v1.1.1 // indirect
	github.com/golang/protobuf v1.2.0
	github.com/golang/snappy v0.0.0-20180518054509-2e65f85255db
	github.com/gorilla/websocket v1.2.0 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.0
	github.com/hashicorp/golang-lru v0.5.0
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jackc/pgx v3.2.0+incompatible
	github.com/jmhodges/levigo v0.0.0-20161115193449-c42d9e0ca023 // indirect
	github.com/kr/logfmt v0.0.0-20140226030751-b84e30acd515 // indirect
	github.com/lib/pq v1.0.0 // indirect
	github.com/magiconair/properties v1.8.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.0.0 // indirect
	github.com/opentracing/opentracing-go v1.0.2
	github.com/pelletier/go-toml v1.2.0 // indirect
	github.com/pkg/errors v0.8.0
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v0.0.0-20180709125804-ae27198cdd90
	github.com/prometheus/client_model v0.0.0-20180712105110-5c3871d89910 // indirect
	github.com/prometheus/common v0.0.0-20180801064454-c7de2306084e // indirect
	github.com/prometheus/procfs v0.0.0-20180725123919-05ee40e3a273 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20180503174638-e2704e165165 // indirect
	github.com/spf13/afero v1.1.2 // indirect
	github.com/spf13/cast v1.2.0 // indirect
	github.com/spf13/cobra v0.0.3
	github.com/spf13/jwalterweatherman v1.0.0 // indirect
	github.com/spf13/pflag v1.0.2
	github.com/spf13/viper v1.0.2
	github.com/stretchr/testify v1.2.2
	github.com/syndtr/goleveldb v0.0.0-20180815032940-ae2bd5eed72d
	github.com/tendermint/btcd v0.0.0-20180816174608-e5840949ff4f // indirect
	github.com/tendermint/ed25519 v0.0.0-20171027050219-d8387025d2b9 // indirect
	github.com/tendermint/go-amino v0.0.0-20180615192746-2106ca61d910 // indirect
	github.com/tendermint/iavl v0.11.0
	github.com/tendermint/tendermint v0.25.0
	github.com/uber/jaeger-client-go v2.14.0+incompatible
	github.com/uber/jaeger-lib v1.5.0 // indirect
	github.com/ugorji/go v1.1.1
	go.etcd.io/bbolt v1.3.0
	golang.org/x/crypto v0.0.0-20180910181607-0e37d006457b
	golang.org/x/net v0.0.0-20180911220305-26e67e76b6c3
	golang.org/x/sys v0.0.0-20180909124046-d0be0721c37e // indirect
	golang.org/x/text v0.3.0 // indirect
	google.golang.org/genproto v0.0.0-20180413175816-7fd901a49ba6 // indirect
	google.golang.org/grpc v1.13.0
	gopkg.in/yaml.v2 v2.2.1 // indirect
)
