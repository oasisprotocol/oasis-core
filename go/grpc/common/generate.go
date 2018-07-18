package common

//go:generate protoc -I ../../../common/api/src --go_out=plugins=grpc:./ ../../../common/api/src/common.proto
