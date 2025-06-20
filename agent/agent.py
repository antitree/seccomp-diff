from flask import Flask, jsonify
from common import containerd, ptrace
import os
import hashlib
import json
import requests
import threading
from datetime import datetime, timedelta

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
UPLOAD_URL = os.getenv("UPLOAD_URL", "https://www.seccompare.com/api/upload")

# The agent will stop attempting to contact the upload site for BACKOFF_DURATION
# after a connection failure.
BACKOFF_DURATION = timedelta(minutes=30)
_backoff_until = None


def _build_payload(profile, image=""):
    payload = profile.copy()
    computed_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {
        "hash": computed_hash,
        "json": payload,
        "image": image.strip() if image else "",
        "source": AGENT_ID,
        "uploadType": "automatic",
    }


def upload_profiles(profiles):
    """Upload a list of seccomp profile payloads asynchronously."""

    def _send():
        global _backoff_until
        if _backoff_until and datetime.utcnow() < _backoff_until:
            return
        try:
            requests.post(UPLOAD_URL, json=profiles, timeout=5)
        except requests.exceptions.ConnectionError:
            _backoff_until = datetime.utcnow() + BACKOFF_DURATION
            app.logger.error("connection error while uploading; backing off")
        except Exception as e:
            app.logger.error(f"failed to upload profiles: {e}")

    threading.Thread(target=_send, daemon=True).start()

@app.route('/containers', methods=['GET'])
def list_containers():
    """Return container details for this node."""
    try:
        info = containerd.get_containers(containerd_socket=CONTAINERD_SOCKET, namespace=NAMESPACE)
    except (FileNotFoundError, PermissionError, containerd.ContainerdConnectionError) as e:
        return jsonify({"error": str(e)}), 500
    for item in info.values():
        item["agent"] = AGENT_ID

    def _process():
        profiles = []
        for item in info.values():
            pid = item.get("pid")
            image = item.get("image")
            if pid:
                try:
                    profile = ptrace.get_seccomp_profile(pid)
                    profiles.append(_build_payload(profile, image))
                except Exception as e:
                    app.logger.error(f"failed to process container {pid}: {e}")
        if profiles:
            upload_profiles(profiles)

    threading.Thread(target=_process, daemon=True).start()
    return jsonify(info)

@app.route('/seccomp/<int:pid>', methods=['GET'])
def seccomp(pid):
    """Return seccomp profile for a given PID in Docker JSON format."""
    profile = ptrace.get_seccomp_profile(pid)
    profile["pid"] = pid
    upload_profiles([_build_payload(profile)])
    return jsonify(profile)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
