#!/usr/bin/python
import argparse
import sys
import traceback

parser = argparse.ArgumentParser(description='Export the latest block for a given runtime from a roothash GRPC service to stdout.')
parser.add_argument('runtime_id', help='Pass this in hex')
parser.add_argument('--remote-addr', default='localhost:42261', help='Connect to the roothash GRPC service at this host:port')
parser.add_argument('--force-tty', help='Force output to tty')
args = parser.parse_args()

import grpc

import roothash_pb2
import roothash_pb2_grpc

if not args.force_tty and sys.stdout.isatty():
    print >>sys.stderr, 'stdout is tty. pass --force-tty to ignore'
    exit(1)

print >>sys.stderr, 'connecting'
with grpc.insecure_channel(args.remote_addr) as channel:
    stub = roothash_pb2_grpc.RootHashStub(channel)
    runtime_id = args.runtime_id.decode('hex')
    latest_block_response = stub.GetLatestBlock(roothash_pb2.LatestBlockRequest(runtime_id=runtime_id))
    block = latest_block_response.block
    block_raw = block.SerializeToString()
    sys.stdout.write(block_raw)
