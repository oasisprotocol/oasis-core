#!/usr/bin/env python3
import argparse
import collections
import os
import re
import sys
import subprocess

SECTION = re.compile(r'^\[(.+)\]')
VERSION = re.compile(r'(version\s*=\s*")(.+)(")')
DEPENDENCIES = re.compile(r'^(?:dependencies|build-dependencies|target\..+?\.dependencies|dependencies\.(\w+))$')
INTERNAL_CRATES = re.compile(r'ekiden-.*')
DOCKER_FROM = re.compile(r'FROM (.+?)(:.+)?$')
CI_IMAGE = re.compile(r'(\s*-\s*image:\s*)(.+?)$')
DOCKER_IMAGE = re.compile(r'(ekiden/development:).+(})')
DEV_IMAGE = re.compile(r'(ekiden/development:).+(")')

# Message used for version bump commits.
VERSION_BUMP_MESSAGE = "Bump version to {version}"
# Message used for release tags.
TAG_MESSAGE = "Release {version}"


def git(*args, **kwargs):
    """Run a Git command and return its output."""
    return subprocess.check_output(['git'] + list(args), **kwargs).decode('utf8').strip()


def cargo(*args, **kwargs):
    """Run a Cargo command."""
    return subprocess.check_call(['cargo'] + list(args), **kwargs)


def docker(*args, **kwargs):
    """Run a Docker command."""
    return subprocess.check_call(['docker'] + list(args), **kwargs)


def get_crates(root_dir):
    """Return crates under the given directory."""
    for root, dirs, files in os.walk(root_dir):
        if 'Cargo.toml' in files:
            # Skip untracked crates.
            if not git('ls-files', os.path.join(root, 'Cargo.toml')):
                continue

            with open(os.path.join(root, 'Cargo.toml')) as config_file:
                config = config_file.readlines()

            # Skip Cargo.tomls without packages.
            for line in config:
                section = SECTION.match(line)
                if section and section.group(1) == 'package':
                    break
            else:
                continue

            yield (root, config)


def replace_version(string, new_version):
    """Replace version in given string."""
    return VERSION.sub('\\g<1>{}\\g<3>'.format(new_version), string)


def bump_version(root_dir, new_version):
    """Bump version of all crates."""
    for path, config in get_crates(root_dir):
        print("Processing crate '{}'".format(path))

        output = []
        current_section = None
        for line in config:
            section = SECTION.match(line)
            if section:
                current_section = section.group(1)

            # Replace version in package metadata.
            if current_section == 'package':
                line = replace_version(line, new_version)

            # Replace version in dependencies.
            dependencies = DEPENDENCIES.match(current_section)
            if dependencies:
                if dependencies.group(1):
                    print(dependencies.group(1))
                    crate = dependencies.group(1)
                else:
                    try:
                        crate = line.split('=')[0].strip()
                    except IndexError:
                        crate = ''

                if INTERNAL_CRATES.match(crate):
                    line = replace_version(line, new_version)

            output.append(line)

        # Write updated Cargo.toml.
        with open(os.path.join(path, 'Cargo.toml'), 'w') as config_file:
            config_file.write(''.join(output))


def commit(version, sign=False):
    """Create a Git commit."""
    # Add all modified files.
    git('add', '--update')

    # Commit changes.
    args = ['commit', '--message', VERSION_BUMP_MESSAGE.format(version=version)]
    if sign:
        args += ['--gpg-sign']
    else:
        args += ['--no-gpg-sign']

    git(*args)


def create_tag(version, sign=False):
    """Create a Git tag."""
    args = ['tag', '--message', TAG_MESSAGE.format(version=version), version]
    if sign:
        args += ['--sign']

    git(*args)


def publish(root_dir):
    """Publish crates."""
    for path, config in get_crates(root_dir):
        print("Publishing crate '{}'".format(path))

        # We must use --no-verify as otherwise we cannot upload packages in arbitrary order.
        cargo('publish', '--no-verify', cwd=path)


def bump_docker_version(root_dir, version, image_dir, dockerfile='Dockerfile'):
    """Bump Dockerfile dependency version."""
    filename = os.path.join(root_dir, image_dir, dockerfile)
    if not git('ls-files', filename):
        print('ERROR: Dockerfile not in Git repository: {}'.format(filename))
        sys.exit(1)

    with open(filename) as dockerfile:
        lines = dockerfile.readlines()

    output = []
    for line in lines:
        upstream = DOCKER_FROM.match(line)
        if upstream:
            line = DOCKER_FROM.sub(r'FROM \1:{}'.format(version), line)

        output.append(line)

    # Write updated Dockerfile.
    with open(filename, 'w') as dockerfile:
        dockerfile.write(''.join(output))


def docker_build(root_dir, version, docker_dir, image):
    """Build and tag a Docker image."""
    docker(
        'build', '--force-rm', '--no-cache', '-t', '{}:{}'.format(image, version), '.',
        cwd=os.path.join(root_dir, docker_dir),
    )


def docker_push(image, tag):
    """Push Docker image."""
    docker('push', '{}:{}'.format(image, tag))


def ci_update_image(root_dir, image, tag):
    """Update image used on CI."""
    filename = os.path.join(root_dir, '.circleci/config.yml')

    with open(filename) as ci_file:
        lines = ci_file.readlines()

    output = []
    for line in lines:
        line = CI_IMAGE.sub(r'\1{}:{}'.format(image, tag), line)

        output.append(line)

    # Write updated Dockerfile.
    with open(filename, 'w') as ci_file:
        ci_file.write(''.join(output))


def script_update_version(root_dir, script, template, tag):
    """Update image used in sgx-enter script."""
    filename = os.path.join(root_dir, 'scripts', script)

    with open(filename) as dev_file:
        lines = dev_file.readlines()

    output = []
    for line in lines:
        line = template.sub(r'\g<1>{}\g<2>'.format(tag), line)

        output.append(line)

    # Write updated Dockerfile.
    with open(filename, 'w') as dev_file:
        dev_file.write(''.join(output))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Make an Ekiden release")
    parser.add_argument('version', type=str,
                        help="New version to release as")
    parser.add_argument('--dev-version', type=str,
                        help="New development version to use after release")
    parser.add_argument('--sign', action='store_true',
                        help="Sign commits and tags")
    parser.add_argument('--git-remote', type=str, default='origin',
                        help="Git remote to push to")
    parser.add_argument('--no-publish', action='store_false', dest='publish',
                        help="Skip Cargo publish")
    parser.add_argument('--no-push', action='store_false', dest='push',
                        help="Skip Git push")
    parser.add_argument('--bump-docker-images', action='store_true',
                        help="Also version bump, build and tag Docker images")
    parser.add_argument('--no-build-docker-images', action='store_false', dest='build_docker_images',
                        help="Skip building Docker images (assume they are already built)")
    args = parser.parse_args()

    # Parse current top-level directory.
    root_dir = git('rev-parse', '--show-toplevel')
    # Ensure Git directory is clean.
    status = git('status', '--porcelain', '--untracked-files=no')
    if status:
        print("ERROR: Repository is not clean, please commit or stash your changes.")
        sys.exit(1)

    # Bump version to new version.
    print("=== Bumping versions to '{}'...".format(args.version))
    bump_version(root_dir, args.version)

    # Build and tag Docker images.
    if args.bump_docker_images:
        print('=== Building and tagging Docker images...')
        bump_docker_version(root_dir, args.version, 'docker/testing')
        ci_update_image(root_dir, 'ekiden/testing', args.version)
        script_update_version(root_dir, '../tools/bin/main.rs', DEV_IMAGE, args.version)
        script_update_version(root_dir, '../docker/deployment/build-images.sh', DOCKER_IMAGE, args.version)

        if args.build_docker_images:
            docker_build(root_dir, args.version, 'docker/development', 'ekiden/development')
            docker_build(root_dir, args.version, 'docker/testing', 'ekiden/testing')

        docker_push('ekiden/development', args.version)
        docker_push('ekiden/testing', args.version)

    # Add modified files and commit version bump.
    print("=== Committing version bump...")
    commit(args.version, sign=args.sign)

    # Create tag.
    print("=== Creating release tag...")
    create_tag(args.version, sign=args.sign)

    # Cargo publish.
    if args.publish:
        print("=== Publishing to Crates.io...")
        publish(root_dir)

    # Change development version when configured.
    if args.dev_version:
        print("=== Bumping versions to '{}'...".format(args.dev_version))
        bump_version(root_dir, args.dev_version)

        print("=== Commiting version bump...")
        commit(args.dev_version, sign=args.sign)

    # Push changes to remote.
    if args.push:
        print("=== Pushing to {}...".format(args.git_remote))
        git('push', args.git_remote)
        git('push', args.git_remote, args.version)
