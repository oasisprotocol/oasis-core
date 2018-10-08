#!/usr/bin/python
import argparse
import sys

parser = argparse.ArgumentParser(description='List contract IDs from a registry GRPC service in hex format.')
parser.add_argument('--remote-addr', default='localhost:42261', help='Connect to the registry GRPC service at this host:port')
parser.add_argument('--timeout', default=1, type=int, help='Disconnect after this timeout in seconds, so that we halt after listing existing contracts. Set to 0 to disable')
args = parser.parse_args()

import grpc

import contract_pb2
import contract_pb2_grpc

TIMEOUT = args.timeout if args.timeout != 0 else None

with grpc.insecure_channel(args.remote_addr) as channel:
    stub = contract_pb2_grpc.ContractRegistryStub(channel)
    try:
        for contracts_response in stub.GetContracts(contract_pb2.ContractsRequest(), timeout=TIMEOUT):
            print contracts_response.contract.id.encode('hex')
    except grpc.RpcError as e:
        if e.code() != grpc.StatusCode.DEADLINE_EXCEEDED:
            raise
