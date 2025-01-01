#!/bin/bash


echo "Installing cert manager"
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.1/cert-manager.yaml

echo "Waiting for for cert manager..."
kubectl --namespace cert-manager wait --for condition=ready pod -l app.kubernetes.io/instance=cert-manager


echo "Installing security profiles operator"
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/main/deploy/operator.yaml

# Optional
curl -L https://github.com/operator-framework/operator-lifecycle-manager/releases/download/v0.30.0/install.sh -o install.sh
chmod +x ./install.sh
./install.sh v0.30.0

echo "Setup complete. Ready to deploy seccomp-diff demos!"

rm ./install.sh