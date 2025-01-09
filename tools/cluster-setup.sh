#!/bin/bash

# Check if the Kubernetes cluster is accessible
if ! kubectl cluster-info > /dev/null 2>&1; then
  echo "Error: Kubernetes cluster is not accessible. Please ensure you are connected to a cluster and try again."
  exit 1
fi

echo "Installing cert manager"
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.1/cert-manager.yaml

echo "Waiting for cert manager..."
kubectl --namespace cert-manager wait --for condition=ready pod -l app.kubernetes.io/instance=cert-manager

echo "Installing security profiles operator"
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/main/deploy/operator.yaml

# Optional installation of operator framework
curl -L https://github.com/operator-framework/operator-lifecycle-manager/releases/download/v0.30.0/install.sh -o install.sh
chmod +x ./install.sh
./install.sh v0.30.0

echo "Setup complete. Ready to deploy seccomp-diff demos!"

rm ./install.sh
