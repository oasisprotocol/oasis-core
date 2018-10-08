roothash_pb2.py: ../../roothash/api/src/roothash.proto
	python -m grpc_tools.protoc -I ../../roothash/api/src --python_out=. --grpc_python_out=. $^

container-deps:
	apt-get install -y python-pip
	pip install grpcio grpcio-tools

.PHONY: container-deps
