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
# seccomp-diff service reachable from the host
curl http://localhost:5000
```

The API server listens on the master's private IP `192.168.56.10`. The kubeconfig
file is patched by the provisioning script so it can be used directly from the
host machine. The `seccomp-diff` service is exposed on `localhost:5000`.

### Loading local images

Each node trusts a local registry running on the master at `192.168.56.10:32000`.
To use your own image without publishing to Docker Hub:

```bash
docker build -t antitree/seccomp-diff .
docker tag antitree/seccomp-diff 192.168.56.10:32000/antitree/seccomp-diff
docker push 192.168.56.10:32000/antitree/seccomp-diff
```

The chart can be installed normally and will pull the image from this registry.
