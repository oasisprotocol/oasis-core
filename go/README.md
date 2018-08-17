# Ekiden Golang Coordination

## Installation

Code is compiled against golang 1.10.

In addition, we expect the following tools, which are present in the
development docker environment:
* [dep](https://github.com/golang/dep)
* [go metalinter](https://github.com/alecthomas/gometalinter)
* [protoc](https://github.com/google/protobuf)
* [protobuf](https://github.com/golang/protobuf) Version 1.0.0

You can build everything by running:
```
make
```

If you want to run individual steps, the following steps are used for compilation:
```
make dep
make generate
make build
```

To lint run:
```
make lint
```
