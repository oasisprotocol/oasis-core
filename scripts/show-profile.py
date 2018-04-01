#!/usr/bin/env python
import argparse

import numpy as np

EKIDEN_PROFILE_PREFIX = 'ekiden-profile:'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=None)
    parser.add_argument('profile', type=str,
                        help="Profile output file")
    parser.add_argument('--sort', type=str, default='-total',
                        help="Sort key and order")
    parser.add_argument('--columns', type=str, default='name,total',
                        help="Comma-separated list of columns")
    args = parser.parse_args()

    # Extract data from profile.
    data = {}
    with open(args.profile) as profile:
        for line in profile:
            if not line.startswith(EKIDEN_PROFILE_PREFIX):
                continue

            line = line[len(EKIDEN_PROFILE_PREFIX):]
            function, duration = line.split('=')
            sec, nsec = duration.split(',')
            duration = int(sec) * 10**9 + int(nsec)

            data.setdefault(function, []).append(duration)

    # Process data.
    processed = []
    for function, durations in data.items():
        processed.append({
            'name': function,
            'total': np.sum(durations),
            'mean': int(np.mean(durations)),
            'min': np.min(durations),
            'max': np.max(durations),
            'std': int(np.std(durations)),
        })

    # Show data.
    descending = args.sort[0] == '-'
    if descending:
        sort_key = args.sort[1:]
    else:
        sort_key = args.sort

    columns = args.columns.split(',')
    columns_format = ' '.join(['{{{}}}'.format(column) for column in columns])

    # Determine column widths.
    column_widths = {}
    for function in processed:
        for column in columns:
            column_width = len(str(function[column]))
            column_widths[column] = max(column_widths.get(column, len(column)), column_width)

    header = {}
    for column in columns:
        header[column] = column.ljust(column_widths[column])

    print(columns_format.format(**header))

    for function in sorted(processed, key=lambda data: data[sort_key], reverse=descending):
        row = {}
        for column in columns:
            row[column] = str(function[column]).ljust(column_widths[column])

        print(columns_format.format(**row))
