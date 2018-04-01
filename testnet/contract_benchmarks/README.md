# Ekiden Testnet for contract benchmarking

This is a simple Ekiden testnet implemented using a single Kubernetes cluster. You can deploy it on a local Kubernetes installation by using [minikube](https://github.com/kubernetes/minikube) (see link for installation instructions).

Once you have your Kubernetes installation running and `kubectl` installed you can use the following commands:

To deploy:
```bash
$ make create experiment=[experiment name]
```

Where the experiment name is one of `token`, `ethtoken`, `dp-credit-scoring`, `iot-learner`.
 
Before running benchmarks on the cluster, one of the nodes should be tagged to run the benchmark client. If no node
is tagged, running the following command will fail with an instruction on how to tag a node. The reason for this is
to ensure that different benchmarks are run in a consistent manner as otherwise Kubernetes may schedule the benchmark
client on an arbitrary node.

To run benchmarks on the cluster:
```bash
$ make benchmark
```

To destroy:
```bash
$ make destroy
```

Note that the destroy command may take some time to complete and may return a timeout. In this case, just run it again and wait until it completes successfully.

## Getting the Ekiden compute node IP and port

If you are using minikube, you can use the following command to get the correct IP and port you need to point your Ekiden client to:
```bash
$ minikube service --url ekiden-[experiment name]-proxy
```

## Running the benchmark client

To run a simple benchmark against the testnet for the `token` contract, build the client with the `benchmark` feature enabled (note that for some reason this doesn't work when called from the workspace using `-p token-client`):
```
$ cd /code/clients/token
$ cargo run --features benchmark -- --benchmark-runs 100 --benchmark-threads 4 --mr-enclave <mr-enclave> --host <host> --port <port>
```

Where `host` and `port` are values obtained from `minikube service` as above.

You can adapt these instructions to run the benchmark for other contracts.

## Building the ekiden/core image

The testnet uses the `ekiden/core` Docker image, which contains prebuilt Ekiden binaries and contracts. In order to (re)build this Docker image, you can run the following command in the top-level Ekiden directory:
```bash
$ ./docker/deployment/build-images.sh
```

This will build `ekiden/core` locally and you can then push the image to your preferred registry.

## Deploying on AWS

Using [kops](https://github.com/kubernetes/kops/blob/master/docs/aws.md) is recommended to set up a Kubernetes cluster on AWS.

To set up AWS in multiple availability zones and use 4 nodes, set up the cluster as following:
```bash
$ kops create cluster --zones us-west-2a,us-west-2b,us-west-2c --node-count 4 ${NAME}
```
