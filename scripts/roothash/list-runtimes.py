#!/usr/bin/python
import argparse
import sys

parser = argparse.ArgumentParser(description='List runtime IDs from a registry GRPC service in hex format.')
parser.add_argument('--remote-addr', default='localhost:42261', help='Connect to the registry GRPC service at this host:port')
parser.add_argument('--timeout', default=1, type=int, help='Disconnect after this timeout in seconds, so that we halt after listing existing runtimes. Set to 0 to disable')
args = parser.parse_args()

import grpc

import runtime_pb2
import runtime_pb2_grpc

TIMEOUT = args.timeout if args.timeout != 0 else None

with grpc.insecure_channel(args.remote_addr) as channel:
    stub = runtime_pb2_grpc.RuntimeRegistryStub(channel)
    try:
        for runtimes_response in stub.GetRuntimes(runtime_pb2.RuntimesRequest(), timeout=TIMEOUT):
            print runtimes_response.runtime.id.encode('hex')
    except grpc.RpcError as e:
        if e.code() != grpc.StatusCode.DEADLINE_EXCEEDED:
            raise
