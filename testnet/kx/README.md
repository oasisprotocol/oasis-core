To set up a Kubernetes cluster on AWS using kops, follow these
directions https://github.com/kubernetes/kops/blob/master/docs/aws.md,
but before you the `kops update cluster ${NAME} --yes`, add the
following steps:

1. Log in to Docker, so that you have access to private repos.
2. Run `kops create secret dockerconfig -f ~/.docker/config.json`.

If you want to set up the Docker credentials after the Kubernetes
cluster already exists, run `kops rolling-update --yes --force` to
recreate the nodes.

---

To create the testnet on a Kubernetes cluster, run `kubectl create -f
kx.yaml`.

To delete the testnet, run `kubectl delete -f kx.yaml`.

To update it after you edit kx.yaml, run `kubectl apply -f
kx.yaml`.
This is not the same as deleting the cluster and recreating it though,
because if you delete a field in the YAML file, it will remain
unchanged instead of changing to the default value.

---

Kops configures the cluster so that masters are permitted to attach
volumes tagged with key `KubernetesCluster` and value equal to the
name of the cluster.

Creating a pod that uses an AWS Elastic Block Store volume might show
that attaching the volume times out, but the last time it happened, it
eventually did attach successfully.
