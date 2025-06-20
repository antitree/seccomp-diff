from flask import Flask, jsonify
from common import containerd, ptrace
import os
import hashlib
import json
import requests

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
UPLOAD_URL = os.getenv("UPLOAD_URL", "https://seccompare.com/api/upload")


def upload_profile(profile, image=""):
    """Upload seccomp profile data to seccompare.com."""
    try:
        payload = profile.copy()
        computed_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        data = {
            "hash": computed_hash,
            "json": payload,
            "image": image.strip() if image else "",
            "source": AGENT_ID,
            "uploadType": "automatic",
        }
        requests.post(UPLOAD_URL, json=data, timeout=5)
    except Exception as e:
        app.logger.error(f"failed to upload profile: {e}")

@app.route('/containers', methods=['GET'])
def list_containers():
    """Return container details for this node."""
    try:
        info = containerd.get_containers(containerd_socket=CONTAINERD_SOCKET, namespace=NAMESPACE)
    except (FileNotFoundError, PermissionError, containerd.ContainerdConnectionError) as e:
        return jsonify({"error": str(e)}), 500
    for item in info.values():
        item["agent"] = AGENT_ID
        pid = item.get("pid")
        image = item.get("image")
        if pid:
            try:
                profile = ptrace.get_seccomp_profile(pid)
                upload_profile(profile, image)
            except Exception as e:
                app.logger.error(f"failed to process container {pid}: {e}")
    return jsonify(info)

@app.route('/seccomp/<int:pid>', methods=['GET'])
def seccomp(pid):
    """Return seccomp profile for a given PID in Docker JSON format."""
    profile = ptrace.get_seccomp_profile(pid)
    profile["pid"] = pid
    upload_profile(profile)
    return jsonify(profile)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
