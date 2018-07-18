# Ekiden Golang Coordination

## Installation

Code is compiled against golang 1.10.

In addition, we expect the following tools, which are present in the
development docker environment:
* [dep](https://github.com/golang/dep)
* [go metalinter](https://github.com/alecthomas/gometalinter)
* [protoc](https://github.com/google/protobuf)
* [protobuf](https://github.com/golang/protobuf) Version 1.0.0

The following steps are used for compilation:
```
dep ensure
go generate ./...
go build -v -o ./ekiden/ekiden ./ekiden
```
