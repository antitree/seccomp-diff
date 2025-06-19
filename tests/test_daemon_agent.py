import json
from daemon.agent import app
from unittest.mock import patch

sample_container = {
    "pid": 1234,
    "seccomp": "\"unconfined\"",
    "image": "busybox",
    "runtime": "runc",
}


def test_list_containers_success():
    with patch('daemon.agent.containerd.get_containers', return_value={"c1": sample_container}), \
         patch('daemon.agent.get_seccomp_profile_json', return_value=({}, '', None)):
        client = app.test_client()
        resp = client.get('/list_containers')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data['containers']) == 1
        assert data['containers'][0]['name'] == 'c1'


def test_list_containers_seccomp_error():
    cont = sample_container.copy()
    cont['seccomp'] = json.dumps({"defaultAction": "SCMP_ACT_ERRNO"})
    with patch('daemon.agent.containerd.get_containers', return_value={"c1": cont}), \
         patch('daemon.agent.get_seccomp_profile_json', side_effect=Exception('boom')):
        client = app.test_client()
        resp = client.get('/list_containers')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'error' in data['containers'][0]

