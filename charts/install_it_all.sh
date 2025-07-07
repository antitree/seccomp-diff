#!/bin/bash
#
## Install cert-manager if it is not already installed (TODO: The helm
# chart might do this one day - see issue 1062 for details):
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.17.2/cert-manager.yaml
kubectl --namespace cert-manager wait --for condition=ready pod -l app.kubernetes.io/instance=cert-manager

# Create the namespace beforehand
export spo_ns=security-profiles-operator
kubectl create ns $spo_ns

# Label and annotate the ns to make it manageable by helm. Ensure it is
# running on the privileged Pod Security Standard.
kubectl label ns $spo_ns \
  app=security-profiles-operator \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/warn=privileged \
  app.kubernetes.io/managed-by=Helm \
  --overwrite=true

kubectl annotate ns $spo_ns \
  "meta.helm.sh/release-name"="security-profiles-operator" \
  "meta.helm.sh/release-namespace"="$spo_ns" \
  --overwrite

# Install the chart from the release URL (or a file path if desired)
helm install security-profiles-operator --namespace security-profiles-operator https://github.com/kubernetes-sigs/security-profiles-operator/releases/download/v0.7.1/security-profiles-operator-0.7.1.tgz
# Or update it with
# helm upgrade --install security-profiles-operator --namespace security-profiles-operator https://github.com/kubernetes-sigs/security-profiles-operator/releases/download/v0.7.1/security-profiles-operator-0.7.1.tgz
