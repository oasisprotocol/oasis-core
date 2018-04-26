#!/usr/bin/env python
"""
Generate a `[patch]` section for a Cargo.toml that substitutes a
GitHub source (https://github.com/oasislabs/ekiden) with a local
checkout (in the path /root/project).

This allows you to build a dependent project with a modified version
of Ekiden.

Usage:

    ./scripts/emit-patch.py >scripts/testing-addendum.toml
"""

import toml

with open('Cargo.toml', 'r') as f:
    workspace_toml = toml.load(f)

print '[patch."https://github.com/oasislabs/ekiden"]'

for path in workspace_toml['workspace']['members']:
    with open('%s/Cargo.toml' % path, 'r') as f:
        package_toml = toml.load(f)
    package_name = package_toml['package']['name']
    print '%s = { path = "/root/project/%s" }' % (package_name, path)
