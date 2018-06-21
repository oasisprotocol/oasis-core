#!/bin/bash
for start in target{,/x86_64-unknown-linux-sgx}/{debug,release}{,/deps}; do
    if [ -d "$start" ]; then
        find "$start" -maxdepth 1 -type f -mtime +7 -print -delete
    fi
done
for start in target{,/x86_64-unknown-linux-sgx}/{debug,release}/{.fingerprint,build,incremental}; do
    if [ -d "$start" ]; then
        find "$start" -maxdepth 1 -mindepth 1 -type d -mtime +7 -print -exec rm -r {} +
    fi
done
