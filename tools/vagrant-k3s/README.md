# Vagrant k3s Cluster

This tool provisions a three-node k3s cluster using Vagrant. The cluster
consists of one master and two workers running Ubuntu 22.04.

## Usage

```bash
cd tools/vagrant-k3s
vagrant up
# kubeconfig will be written to ./kubeconfig
export KUBECONFIG=$(pwd)/kubeconfig
kubectl get nodes
```

The API server listens on the master's private IP `192.168.56.10`. The kubeconfig
file is patched by the provisioning script so it can be used directly from the
host machine.
