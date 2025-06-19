import os
from flask import Flask, jsonify
from common import containerd
from common.ptrace import get_seccomp_profile_json

NODE_NAME = os.environ.get("NODE_NAME", "unknown")

app = Flask(__name__)

@app.route('/containers', methods=['GET'])
def list_containers():
    containers = containerd.get_containers(namespace="k8s.io")
    result = []
    for name, data in containers.items():
        data['node'] = NODE_NAME
        result.append(data)
    return jsonify({'containers': result})

@app.route('/seccomp/<int:pid>', methods=['GET'])
def get_seccomp(pid):
    profile, full, dis = get_seccomp_profile_json(pid)
    return jsonify({
        'profile': profile,
        'full': full,
        'summary': dis.syscallSummary
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
