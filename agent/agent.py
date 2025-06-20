from flask import Flask, jsonify
from common import containerd, ptrace
import os

app = Flask(__name__)

# Namespace and socket path can be configured via env vars. If the socket
# isn't provided, attempt to guess common paths used by containerd and k3s.
CONTAINERD_SOCKET = os.getenv("CONTAINERD_SOCKET")
if not CONTAINERD_SOCKET:
    for guess in ("/run/containerd/containerd.sock", "/run/k3s/containerd/containerd.sock"):
        if os.path.exists(guess):
            CONTAINERD_SOCKET = guess
            break
    else:
        CONTAINERD_SOCKET = "/run/containerd/containerd.sock"
NAMESPACE = os.getenv("CONTAINER_NAMESPACE", "k8s.io")
AGENT_ID = os.getenv("HOSTNAME", "agent")

@app.route('/containers', methods=['GET'])
def list_containers():
    """Return container details for this node."""
    info = containerd.get_containers(containerd_socket=CONTAINERD_SOCKET, namespace=NAMESPACE)
    for item in info.values():
        item["agent"] = AGENT_ID
    return jsonify(info)

@app.route('/seccomp/<int:pid>', methods=['GET'])
def seccomp(pid):
    """Return seccomp details for a given PID."""
    filters, dis = ptrace.get_seccomp_filters(pid)
    summary = dis.syscallSummary if dis else {}
    return jsonify({"pid": pid, "filters": filters, "summary": summary})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
