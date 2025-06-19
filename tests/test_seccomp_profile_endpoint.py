from daemon.agent import app
from unittest.mock import patch

class FakeDis:
    def __init__(self):
        self.syscallSummary = {"total": {"count": 1}}


def test_seccomp_profile_endpoint():
    fake_profile = {"defaultAction": "SCMP_ACT_ALLOW"}
    with patch('daemon.agent.get_seccomp_profile_json', return_value=(fake_profile, 'FULL', FakeDis())):
        client = app.test_client()
        resp = client.get('/seccomp_profile/123')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['profile'] == fake_profile
        assert data['full'] == 'FULL'
        assert data['total'] == 1
