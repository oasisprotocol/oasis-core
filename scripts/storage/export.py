#!/usr/bin/python
import argparse
import itertools
import os
import sys

import common

parser = argparse.ArgumentParser(description='Export storage items from a storage GRPC service to stdout.')
parser.add_argument('--remote-addr', default='localhost:42261', help='Connect to the storage GRPC service at this host:port')
parser.add_argument('--scratch-dir', default='/tmp', help='Use this location for temporary storage')
parser.add_argument('--batch-size', type=int, default=1000, help='Request this many items at a time with GetBatch')
parser.add_argument('--force-tty', help='Force output to tty')
args = parser.parse_args()

import grpc
import tqdm

import storage_pb2
import storage_pb2_grpc

if not args.force_tty and sys.stdout.isatty():
    print >>sys.stderr, 'stdout is tty. pass --force-tty to ignore'
    exit(1)

BATCH_SIZE = args.batch_size
KEYS_TEMP = args.scratch_dir + '/storage-export-keys.dat'

print >>sys.stderr, 'connecting'
with grpc.insecure_channel(args.remote_addr) as channel:
    stub = storage_pb2_grpc.StorageStub(channel)

    # Phase 1: download keys and expiry
    print >>sys.stderr, 'getting keys'
    total = 0
    with open(KEYS_TEMP, 'wb') as f:
        for get_keys_response in tqdm.tqdm(stub.GetKeys(storage_pb2.GetKeysRequest())):
            total += 1
            get_keys_response_raw = get_keys_response.SerializeToString()
            print >>f, len(get_keys_response_raw)
            f.write(get_keys_response_raw)

    # Phase 2: download values
    with open(KEYS_TEMP, 'rb') as f:
        items = tqdm.tqdm(common.read_messages(f, storage_pb2.GetKeysResponse), total=total)
        while True:
            batch = list(itertools.islice(items, BATCH_SIZE))
            if not batch:
                break
            keys = [item.key for item in batch]
            get_batch_response = stub.GetBatch(storage_pb2.GetBatchRequest(ids=keys))
            for item, value in zip(batch, get_batch_response.data):
                insert_request_raw = storage_pb2.InsertRequest(data=value, expiry=item.expiry).SerializeToString()
                print len(insert_request_raw)
                sys.stdout.write(insert_request_raw)

# Clean up
print >>sys.stderr, 'cleaning up'
os.remove(KEYS_TEMP)
