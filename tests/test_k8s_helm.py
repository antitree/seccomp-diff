import os
import shutil
import subprocess
import uuid

import pytest

MINIKUBE = shutil.which("minikube")
HELM = shutil.which("helm")
DOCKER = shutil.which("docker")

RUN_K8S_TESTS = os.getenv("RUN_K8S_TESTS")


@pytest.mark.skipif(
    not RUN_K8S_TESTS or not MINIKUBE or not HELM or not DOCKER,
    reason="K8S tests require RUN_K8S_TESTS=1 and minikube, helm, docker installed",
)
def test_seccomp_diff_helm_chart():
    def run(cmd, **kwargs):
        kwargs.setdefault("check", True)
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, **kwargs)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return result

    run("minikube start --wait=true")
    try:
        commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], text=True).strip()
        image = f"seccomp-diff:{commit}"
        run(f"docker build -t {image} .")
        run(f"minikube image load {image}")

        release = f"scdiff-{uuid.uuid4().hex[:6]}"
        run(
            f"helm install {release} charts/seccomp-diff "
            f"--set image.repository=seccomp-diff --set image.tag={commit} "
            f"--set image.pullPolicy=Never --wait"
        )
        run("kubectl get pods -n seccomp-diff")
    finally:
        run("helm uninstall $(helm list -q) || true", check=False)
        run("minikube delete", check=False)

