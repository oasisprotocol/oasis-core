#!/usr/bin/python3
import base64
import collections
import json
import sys
import typing

import cbor

def default_hexbytes(o):
    if type(o) is bytes:
        return o.hex()
    raise TypeError('defer')

compute_commitments = []
merge_commitments = []
ended_round = 0

def end_round(round):
    print('%%%%%% had %d compute commitments and %d merge commitments' % (
        len(compute_commitments),
        len(merge_commitments),
    ))
    compute_commitments.clear()
    merge_commitments.clear()
    global ended_round
    ended_round = round
    print()

for line in sys.stdin:
    if line[0] != '{':
        print('encountered a line that isn\'t a JSON object', file=sys.stderr)
        continue
    try:
        record = json.loads(line)
    except ValueError as e:
        print('couldn\'t parse JSON:' + e, file=sys.stderr)
        continue
    if 'log_event' in record:
        if record['log_event'] == 'roothash/compute_discrepancy_detected':
            print('compute discrepancy after round', ended_round)
            # runtimes[runtime_id][header_cbor] = set(signers)
            runtimes: typing.DefaultDict[bytes, typing.DefaultDict[bytes, typing.Set[bytes]]] = \
                collections.defaultdict(lambda: collections.defaultdict(set))
            for tx in compute_commitments:
                runtime_id = tx['ComputeCommit']['id']
                commitments = runtimes[runtime_id]
                for c in tx['ComputeCommit']['commits']:
                    signer = c['signature']['public_key']
                    body = cbor.loads(c['untrusted_raw_value'])
                    header = body['header']
                    header_cbor = cbor.dumps(header, sort_keys=True)
                    signers = commitments[header_cbor]
                    signers.add(signer)
            for runtime_id, commitments in runtimes.items():
                if len(commitments) == 1:
                    print('no discrepancy in runtime', runtime_id.hex())
                    continue
                print('discrepancy in runtime', runtime_id.hex())
                for header_cbor, signers in commitments.items():
                    for signer in signers:
                        print('from', signer.hex())
                    header = cbor.loads(header_cbor)
                    print(json.dumps(header, sort_keys=True, indent=2, default=default_hexbytes))
        elif record['log_event'] == 'roothash/merge_discrepancy_detected':
            print('merge discrepancy after round %d. commitments:' % ended_round)
            for c in merge_commitments:
                # TODO: print diagnostics
                print(c)
    if record['module'] == 'abci-mux':
        if record['msg'] == 'dispatching':
            if record['is_check_only']:
                continue
            if record['app'] == '999_roothash':
                tx_raw = base64.b64decode(record['tx'])
                tag = tx_raw[0]
                if tag != 0x02:
                    print('wrong transaction tag 0x%02x' % tag)
                    continue
                tx = cbor.loads(tx_raw[1:])
                if 'ComputeCommit' in tx:
                    print('%%% received compute commit')
                    compute_commitments.append(tx)
                elif 'MergeCommit' in tx:
                    print('%%% received merge commit')
                    merge_commitments.append(tx)
                else:
                    print('%%% received other transaction')
    elif record['module'] == 'tendermint/roothash':
        if record['msg'] == 'finalized round':
            print('%%%%%% round %d finalized' % record['round'])
            end_round(record['round'])
        elif record['msg'] == 'checkCommittees: new committee, transitioning round':
            print('%%%%%% round %d abandoned for new committee' % record['round'])
            end_round(record['round'])
