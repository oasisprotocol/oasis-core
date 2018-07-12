#!/usr/bin/env python
"""
Starts Tendermint docker container and setups docker networking so
Ekiden and Tendermint containers can be connected.

Script assumes Ekiden container is allready running and by default will
attach to container named "ekiden-*****". Use "--ekiden-name" to overide
the default name.

Usage:
    ./scripts/tendermint.py

For help, see:
    ./scripts/tendermint.py -h
"""

import argparse
import subprocess
import sys
import os


TENDERMINT_IMAGE_TAG = "docker.io/tendermint/tendermint:0.22.0"


def get_container_id(name):
    output = subprocess.check_output(
        # Prefix match.
        ['docker', 'ps', '-q', '-f', 'name=^/{}'.format(name)]
    )
    return output.split('\n')[0]


def container_running(name):
    container_id = get_container_id(name)
    return not container_id == ''


def cleanup_container(container_name):
    """ Removes exited container with *container_name* name. """

    command = ['docker', 'ps', '-aq', '-f', 'status=exited',
               '-f', 'name={}'.format(container_name)]
    output = subprocess.check_output(command).split('\n')[0]
    if output != '':
        subprocess.check_call(['docker', 'rm', output])


def run_tendermint(container_name, ekiden_container, state_dir):
    cleanup_container(container_name)
    ekiden_container = get_container_id(ekiden_container)

    # Create state directory.
    try:
        os.makedirs(state_dir)
        os.chmod(state_dir, 0777)
    except OSError:
        pass

    command = [
        'docker', 'run',
        '--name', container_name,
        '--network=container:{}'.format(ekiden_container),
        '-v', '{}:/tendermint'.format(state_dir),
        '--rm',
        TENDERMINT_IMAGE_TAG
    ]
    subprocess.check_call(command + ['init'])
    subprocess.check_call(command + ['node', '--consensus.create_empty_blocks=false'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=None)
    parser.add_argument('--state-dir', type=str, default='/tmp/ekiden-tendermint',
                          help="Path to Tendermint state directory. Default: /tmp/ekiden-tendermint")
    parser.add_argument('--ekiden-name', type=str, default='ekiden-',
                          help="Running ekiden container name.")
    parser.add_argument('--name', type=str, default='tendermint',
                          help="Tendermint container name. Default: tendermint")

    args = parser.parse_args()

    state_dir = args.state_dir
    ekiden_container = args.ekiden_name
    tendermint_container = args.name

    # Checked if passed ekiden container is running
    if not container_running(ekiden_container):
        print("ERROR: Ekiden container: '{}' not running!".format(ekiden_container))
        sys.exit(1)

    # Check if Tendermint is allready running
    if not container_running(tendermint_container):
        # If not: run it (& clean any old exited Tendermint containers)
        run_tendermint(tendermint_container, ekiden_container, state_dir)
    else:
        print("ERROR: Tendermint container: '{}, allready running!".format(
            tendermint_container))
