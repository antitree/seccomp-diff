import os
from flask import Flask, jsonify
from common import containerd, docker
from common.seccomp_json import get_seccomp_profile_json

app = Flask(__name__)
NODE_NAME = os.environ.get("NODE_NAME", os.uname().nodename)
MODE = os.environ.get("MODE", "k8s")  # k8s or Docker

@app.route('/list_containers', methods=['GET'])
def list_containers():
    if MODE == "Docker":
        containers = docker.get_containers()
    else:
        containers = containerd.get_containers(namespace="k8s.io")
    result = []
    for name, data in containers.items():
        data['name'] = name
        data['node'] = NODE_NAME
        result.append(data)
    return jsonify({"containers": result})

@app.route('/seccomp_profile/<int:pid>', methods=['GET'])
def seccomp_profile(pid):
    profile, full, dis = get_seccomp_profile_json(pid)
    total = dis.syscallSummary.get("total", {}).get("count", 0)
    return jsonify({"profile": profile, "full": full, "total": total})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
