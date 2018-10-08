roothash_pb2.py: ../../roothash/api/src/roothash.proto ../../registry/api/src/runtime.proto ../../common/api/src/common.proto
	python -m grpc_tools.protoc -I ../../roothash/api/src -I ../../registry/api/src -I ../.. --python_out=. --grpc_python_out=. $^

container-deps:
	apt-get install -y python-pip
	pip install grpcio grpcio-tools

.PHONY: all container-deps
