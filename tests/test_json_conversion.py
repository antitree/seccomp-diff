from common.seccomp_json import _parse_action, _scmp_to_string, disassembler_to_json, json_to_summary

class FakeDis:
    def __init__(self):
        self.arch = 'X86_64'
        self.defaultAction = 'ERRNO(99)'
        self.syscallSummary = {
            'open': {'count': 1, 'action': 'ALLOW'},
            'kill': {'count': 1, 'action': 'KILL'},
            'total': {'count': 2}
        }


def test_parse_action_errno():
    act, num = _parse_action('ERRNO(99)')
    assert act == 'SCMP_ACT_ERRNO'
    assert num == 99


def test_scmp_to_string():
    assert _scmp_to_string('SCMP_ACT_ERRNO', 1) == 'ERRNO(1)'
    assert _scmp_to_string('SCMP_ACT_ALLOW', None) == 'ALLOW'


def test_conversion_roundtrip():
    dis = FakeDis()
    profile = disassembler_to_json(dis)
    assert profile['defaultAction'] == 'SCMP_ACT_ERRNO'
    assert profile['defaultErrnoRet'] == 99
    assert len(profile['syscalls']) == 2

    summary, default_action = json_to_summary(profile)
    assert summary['open']['action'] == 'ALLOW'
    assert summary['kill']['action'] == 'KILL'
    assert default_action == 'ERRNO(99)'
