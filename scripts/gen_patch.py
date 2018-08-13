#!/usr/bin/env python3

"""Scans a cargo repo and prints a list of dependencies.

Usage: python3 gen_patch.py /path/to/repo

Example:

python3 gen_patch.py ekiden/ >> Cargo.toml
head Cargo.toml
# [patch.'https://github.com/oasislabs/ekiden']
# ekiden-tools = { path = "/path/to/ekiden/ekiden/tools" }
# ekiden-epochtime = { path = "/path/to/ekiden/ekiden/epochtime" }
# ekiden-contract-untrusted = { path = "/path/to/ekiden/ekiden/contract/untrusted" }
# ...
"""

import argparse
import os.path as osp
import os

import toml


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('repo', type=osp.abspath, help='path to local cargo repo')
    args = parser.parse_args()

    for dir_path, _dir_names, file_names in os.walk(args.repo):
        for name in file_names:
            if name != 'Cargo.toml':
                continue
            with open(osp.join(dir_path, 'Cargo.toml')) as f_cargo:
                pkg_info = toml.load(f_cargo).get('package')
            if not pkg_info:
                continue
            print(f'{pkg_info["name"]} = {{ path = "{dir_path}" }}')


if __name__ == '__main__':
    main()
