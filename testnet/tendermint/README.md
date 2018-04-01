# Instructions
## Setting up prerequisites
1. Install the AWS CLI tool.
   They say you can do it with pip, using `pip install awscli --upgrade --user`.
   Make sure you have `$HOME/.local/bin` in `PATH` if you install it that way.
2. Get yourself an [AWS access key](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) and enter it in `aws configure`.
   Don't enter a default region, because we use many regions.
3. Get the SSH keys archive.
   These aren't under version control.
   Unpack the keys into this directory.
   It should put the .pem files into the keys directory.
4. In the AWS EC2 console, in each region that the cluster occupies (currently only N. California), in the `tendermint-base` security group, add an inbound rule to allow your computer to connect through SSH and an inbound rule to allow your compute node to access the consensus node (TCP port 9002).

## Starting the cluster
1. In the AWS EC2 console, in each region that the cluster occupies, in the `tendermint` security group, delete all the inbound rules.
   (Should find a way to automate this.)
2. Start the EC2 instances belonging to the cluster (currently ekidentm-val{1,2,3} in N. California).
   This dynamically assigns them IP addresses.
3. Locally, switch to the testnet/tendermint directory.
   The scripts and configurations depend on this being the current working directory.
4. Run `touch launch.stamp` to indicate that the instances have been launched.
   This marks cluster management targets as out of date, so that they will run.
5. Run `make connect`, which uses the AWS CLI tool to get the public IP addresses of the instances and sets up the ssh_config and known_hosts files.
   This writes the public IP addresses to ips.txt.
   The resulting ssh_config assigns simple names `val1`-`val3` so you can easily `ssh`/`scp` without worrying about IP address and key.
   It also sets up opportunistic connection sharing so that we can avoid repeated SSH handshakes while running the experiments.
   The get_ips.sh script has the instance IDs hardcoded, so update it if the instances change.
   The create_ssh_config.sh script has a template that associates a region-specific key with each VM, so update it if the key associations change.
   The create_known_hosts.sh script has a template with the host keys of the VMs hardcoded, so update it if the host keys change.
6. Run `make authorize.stamp`, which uses the AWS CLI tool to populate the `tendermint` security groups.
   The authorize_security_groups.sh script has a list of regions in which to do this hardcoded, so update it if the regions change.

## Connecting to the cluster
In a separate shell, run `. start_control.sh` (sourcing it, rather than fork-exec-ing it), which sets up background jobs to connect to each VM.
I recommend that you do this in a separate shell, so the jobs don't get mixed up with other things.
These connections will be used in subsequent operations.
If you don't do this, the commands will each connect individually, which can be a lot slower.

To disconnect, run `kill $(jobs -p)` to kill the jobs.

## Setting up the cluster
**This is already done**, but if we ever need to do it again, here's how.

1. Run `make genesis.stamp` to download a copy of Tendermint and upload it to the VMs and set up validator keys and a blockchain.
2. Build the consensus node in release mode.
3. Run `make install-consensus.stamp` to upload the consensus node program to the VMs.

## Running the network
In a separate shell, run `./run_servers.sh`.
This will block until the servers exit.

## Stopping the network
Run `make stop`.
If you also want to erase the state, run `make clear` after that.
4. Run `./cmd.sh killall run` to kill the client, the primary, and the servers.

# Utilities
## cmd.sh
```
./cmd.sh command args...
```
Run a command on all VMs in parallel.

## cmd_serial.sh
```
./cmd_serial.sh command args...
```
Run a command on all VMs one at a time.

## send.sh
```
./send.sh file
```
Upload a file to all VMs, into the home directory there, in parallel.

# Handy commands
```
killall ssh
```
If you interrupt one of the utilities that does things in parallel, its jobs will still exist.
This kills SSH clients that may be out there in limbo.

```
./cmd.sh pgrep tendermint
```
Check for Tendermint processes on all VMs.
Would also be useful to check for `consensus`.

```
./cmd_serial.sh true
```
Test that each VM is responsive.

# Adding VMs to the cluster
* Add instance ID to get_ips.sh
* Add entry to create_ssh_config.sh
* Add host key to create_known_hosts.sh
* Add lines and entries and stuff to all the scripts
* Upload Tendermint and consensus programs
* Somehow configure Tendermint, including setting up validator keys and peer seeds.
  Probably just recreating all validator keys and the genesis.json would work.

**If the added VMs cover more regions, then additionally:**
* If the VMs need new keys, add those to the keys archive
* Add entries to authorize_security_groups.sh
