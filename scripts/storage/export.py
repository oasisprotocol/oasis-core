#!/usr/bin/python
import argparse
import sys

parser = argparse.ArgumentParser(description='Export storage items from a storage GRPC service to stdout.')
parser.add_argument('--remote-addr', default='localhost:42261', help='Connect to the storage GRPC service at this host:port')
parser.add_argument('--batch-size', type=int, default=1000, help='Request this many items at a time with GetBatch')
parser.add_argument('--max-receive-message-length', type=int, default=4 * 1024 * 1024, help='Set this limit in the GRPC client, in case the list of keys is too large')
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

grpc_opts = [('grpc.max_receive_message_length', args.max_receive_message_length)]
print >>sys.stderr, 'connecting'
with grpc.insecure_channel(args.remote_addr, options=grpc_opts) as channel:
    stub = storage_pb2_grpc.StorageStub(channel)
    print >>sys.stderr, 'getting keys',
    get_keys_response = stub.GetKeys(storage_pb2.GetKeysRequest())
    total = len(get_keys_response.keys)
    print >>sys.stderr, '%d items' % total

    for idx_start in tqdm.trange(0, total, BATCH_SIZE):
        idx_end = idx_start + BATCH_SIZE
        get_batch_response = stub.GetBatch(storage_pb2.GetBatchRequest(ids=get_keys_response.keys[idx_start:idx_end]))
        for value, expiry in zip(get_batch_response.data, get_keys_response.expiry[idx_start:idx_end]):
            insert_request_raw = storage_pb2.InsertRequest(data=value, expiry=expiry).SerializeToString()
            print len(insert_request_raw)
            sys.stdout.write(insert_request_raw)
