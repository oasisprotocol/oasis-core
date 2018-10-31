#!/usr/bin/python
import argparse
import itertools
import sys

import common

parser = argparse.ArgumentParser(description='Import storage items to a storage GRPC service from stdin.')
parser.add_argument('--remote-addr', default='localhost:42261', help='Connect to the storage GRPC service at this host:port')
parser.add_argument('--batch-size', type=int, default=1000, help='Send this many items at a time with InsertBatch')
parser.add_argument('--current-epoch', type=int, required=True, help='The current epoch, for sending the right expiry times')
parser.add_argument('--force-tty', help='Force input from tty')
args = parser.parse_args()

import grpc

import storage_pb2
import storage_pb2_grpc

if not args.force_tty and sys.stdin.isatty():
    print >>sys.stderr, 'stdin is tty. pass --force-tty to ignore'
    exit(1)

BATCH_SIZE = args.batch_size
CURRENT_EPOCH = args.current_epoch

print >>sys.stderr, 'connecting'
with grpc.insecure_channel(args.remote_addr) as channel:
    stub = storage_pb2_grpc.StorageStub(channel)
    items = common.read_messages(sys.stdin, storage_pb2.InsertRequest)
    items_iter = iter(items)
    print >>sys.stderr, 'importing items'
    while True:
        batch = list(itertools.islice(items_iter, BATCH_SIZE))
        if not batch:
            break
        for item in batch:
            if item.expiry < CURRENT_EPOCH:
                continue
            item.expiry -= CURRENT_EPOCH
        stub.InsertBatch(storage_pb2.InsertBatchRequest(items=batch))
