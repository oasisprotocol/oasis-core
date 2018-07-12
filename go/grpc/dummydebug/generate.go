package dummydebug

//go:generate protoc -I ../../../node/dummy/api/src --go_out=plugins=grpc,import_path=dummydebug:./ ../../../node/dummy/api/src/dummy_debug.proto
