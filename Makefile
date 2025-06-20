image:
	docker build -t antitree/seccomp-diff .
	docker push antitree/seccomp-diff

# Build test image and run Kubernetes integration tests using Vagrant
# Requires Vagrant, helm, kubectl, docker

test/k8s:
	docker build -t antitree/seccomp-diff:test .
	docker push antitree/seccomp-diff:test
	RUN_VAGRANT_TESTS=1 pytest tests/test_vagrant_k8s.py

# Build and push test image only
test/image:
	docker build -t antitree/seccomp-diff:test .
	docker push antitree/seccomp-diff:test

# Deploy Helm chart to k3s using the test image and socket path
test/k3s:
	helm install seccomp-diff charts/seccomp-diff \
		--set image.tag=test \
		--set agent.containerdSocket=/run/k3s/containerd/containerd.sock

test/py:
	pytest
