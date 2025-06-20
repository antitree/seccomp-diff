image:
	docker build -t antitree/seccomp-diff .
	docker push antitree/seccomp-diff

# Build test image and run Kubernetes integration tests using Vagrant
# Requires Vagrant, helm, kubectl, docker

test/k8s:
	docker build -t antitree/seccomp-diff:test .
	docker push antitree/seccomp-diff:test
	RUN_VAGRANT_TESTS=1 pytest tests/test_vagrant_k8s.py

test/py:
	pytest
