import os
from flask import Flask, jsonify
from common import containerd, docker
from common.seccomp_json import get_seccomp_profile_json
import json

app = Flask(__name__)
NODE_NAME = os.environ.get("NODE_NAME", os.uname().nodename)
MODE = os.environ.get("MODE", "k8s")  # k8s or Docker

@app.route('/list_containers', methods=['GET'])
def list_containers():
    print(f"[{NODE_NAME}] listing containers (mode={MODE})")
    if MODE == "Docker":
        containers = docker.get_containers()
        print(f"[{NODE_NAME}] retrieved {len(containers)} containers from Docker")
    else:
        try:
            containers = containerd.get_containers(namespace="k8s.io")
            print(f"[{NODE_NAME}] retrieved {len(containers)} containers from containerd")
        except Exception as e:
            print(f"[{NODE_NAME}] failed to query containerd: {e}")
            return jsonify({"error": "containerd query failed"}), 500

    result = []
    for name, data in containers.items():
        data['name'] = name
        data['node'] = NODE_NAME
        seccomp_field = json.loads(data.get('seccomp', '"unconfined"'))
        if seccomp_field != "unconfined" and data.get('pid'):
            try:
                get_seccomp_profile_json(int(data['pid']))
            except Exception as e:
                data['error'] = f"seccomp profile extraction failed: {e}"
                print(f"[{NODE_NAME}] error extracting seccomp for {name}: {e}")
        result.append(data)
    return jsonify({"containers": result})

@app.route('/seccomp_profile/<int:pid>', methods=['GET'])
def seccomp_profile(pid):
    profile, full, dis = get_seccomp_profile_json(pid)
    total = dis.syscallSummary.get("total", {}).get("count", 0)
    return jsonify({"profile": profile, "full": full, "total": total})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
