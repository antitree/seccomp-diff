import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import requests

VAGRANT = shutil.which("vagrant")
HELM = shutil.which("helm")
KUBECTL = shutil.which("kubectl")
DOCKER = shutil.which("docker")
RUN_VAGRANT_TESTS = os.getenv("RUN_VAGRANT_TESTS")


def run(cmd, cwd=None, env=None, check=True):
    result = subprocess.run(cmd, shell=True, cwd=cwd, env=env,
                            capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd)
    return result


@pytest.mark.skipif(
    not RUN_VAGRANT_TESTS or not all([VAGRANT, HELM, KUBECTL, DOCKER]),
    reason="Vagrant tests require RUN_VAGRANT_TESTS=1 and vagrant, helm, kubectl, docker installed",
)
def test_agent_seccomp_dump():
    cluster_dir = Path("tools/vagrant-k3s")
    env = os.environ.copy()
    env["KUBECONFIG"] = str(cluster_dir / "kubeconfig")

    run("vagrant up --provision", cwd=cluster_dir)
    try:
        commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], text=True).strip()
        image = f"seccomp-diff:{commit}"
        run(f"docker build -t {image} .")
        run(f"docker tag {image} 192.168.56.10:32000/{image}")
        run(f"docker push 192.168.56.10:32000/{image}")

        release = f"scdiff-{uuid.uuid4().hex[:6]}"
        run(
            f"helm install {release} charts/seccomp-diff "
            f"--set image.repository=192.168.56.10:32000/seccomp-diff "
            f"--set image.tag={commit} --set image.pullPolicy=IfNotPresent --wait",
            env=env,
        )
        run("kubectl wait --for=condition=Ready pods --all -n seccomp-diff", env=env)
        run("kubectl run test-nginx --image=nginx --restart=Never", env=env)
        run("kubectl wait --for=condition=Ready pod/test-nginx", env=env)

        agent_pod = subprocess.check_output(
            "kubectl get pods -n seccomp-diff -l app=seccomp-diff-agent -o jsonpath='{.items[0].metadata.name}'",
            shell=True,
            text=True,
            env=env,
        ).strip("'")
        pf = subprocess.Popen(["kubectl", "port-forward", agent_pod, "18000:8000", "-n", "seccomp-diff"], env=env)
        try:
            time.sleep(5)
            containers = requests.get("http://localhost:18000/containers").json()
            pid = None
            for c in containers.values():
                if c.get("name") == "test-nginx":
                    pid = c.get("pid")
                    break
            assert pid, "pid not found"
            resp = requests.get(f"http://localhost:18000/seccomp/{pid}").json()
            assert resp.get("filters"), "no seccomp policy returned"
        finally:
            pf.terminate()
            pf.wait()
    finally:
        run("kubectl delete pod test-nginx", env=env, check=False)
        run("helm uninstall $(helm list -q) || true", env=env, check=False)
        run("vagrant destroy -f", cwd=cluster_dir, check=False)
