#!/usr/bin/python
import argparse
import sys
import traceback

parser = argparse.ArgumentParser(description='Export the latest blocks for given contracts from a roothash GRPC service to stdout.')
parser.add_argument('contract_id', nargs='*', help='Pass these in hex')
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
    genesis_blocks = []
    for contract_id_hex in args.contract_id:
        contract_id = contract_id_hex.decode('hex')
        print >>sys.stderr, 'contract_id', contract_id_hex,
        try:
            latest_block_response = stub.GetLatestBlock(roothash_pb2.LatestBlockRequest(contract_id=contract_id))
            block = latest_block_response.block
            print >>sys.stderr, 'state_root', block.header.state_root.encode('hex')
            genesis_blocks.append(roothash_pb2.GenesisBlock(contract_id=contract_id, block=block))
        except:
            print >>sys.stderr, 'couldn\'t get latest block'
            traceback.print_exc()
    genesis_blocks_raw = roothash_pb2.GenesisBlocks(genesis_blocks=genesis_blocks).SerializeToString()
    sys.stdout.write(genesis_blocks_raw)
