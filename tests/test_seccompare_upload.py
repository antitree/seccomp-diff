import json
from unittest.mock import patch, Mock

from common.seccompare import upload_if_missing


def test_upload_new_profile():
    profile = {'syscalls': []}
    payload = json.dumps(profile, sort_keys=True).encode('utf-8')
    hash_val = __import__('hashlib').sha256(payload).hexdigest()

    check_resp = Mock(status_code=200, json=lambda: {'exists': False})
    upload_resp = Mock(status_code=200)

    with patch('requests.post', side_effect=[check_resp, upload_resp]) as mock_post:
        result = upload_if_missing(profile, 'image:latest')
        assert result['hash'] == hash_val
        assert result['exists'] is False
        assert result['uploaded'] is True
        assert result['upload_status'] == 200
        assert mock_post.call_count == 2


def test_check_hash_failure():
    profile = {'syscalls': []}
    check_resp = Mock(status_code=500)
    with patch('requests.post', return_value=check_resp):
        result = upload_if_missing(profile)
        assert 'error' in result
        assert result['uploaded'] is False
