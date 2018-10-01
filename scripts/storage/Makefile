storage_pb2.py: ../api/src/storage.proto
	python -m grpc_tools.protoc -I ../api/src --python_out=. --grpc_python_out=. $<

container-deps:
	apt-get install -y python-pip python-tqdm
	pip install grpcio grpcio-tools

.PHONY: container-deps
