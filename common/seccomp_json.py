import re
from typing import Optional
from common.ptrace import get_seccomp_filters, get_default_seccomp


def _parse_action(action: str):
    """Convert action string like 'ALLOW' or 'ERRNO(1)' to SCMP action and errno."""
    if not action:
        return "SCMP_ACT_ALLOW", None
    base = action.split("/")[0]
    m = re.match(r"([A-Z_]+)(?:\((\d+)\))?", base)
    if m:
        name = m.group(1)
        errno = int(m.group(2)) if m.group(2) else None
    else:
        name = base
        errno = None
    mapping = {
        "ALLOW": "SCMP_ACT_ALLOW",
        "ERRNO": "SCMP_ACT_ERRNO",
        "KILL": "SCMP_ACT_KILL",
        "KILL_PROCESS": "SCMP_ACT_KILL",
        "KILL_THREAD": "SCMP_ACT_KILL",
        "TRACE": "SCMP_ACT_TRACE",
        "TRAP": "SCMP_ACT_TRAP",
        "LOG": "SCMP_ACT_LOG",
    }
    return mapping.get(name, "SCMP_ACT_ALLOW"), errno



def _scmp_to_string(action: str, errno: Optional[int]):
    reverse = {
        "SCMP_ACT_ALLOW": "ALLOW",
        "SCMP_ACT_KILL": "KILL",
        "SCMP_ACT_KILL_PROCESS": "KILL",
        "SCMP_ACT_KILL_THREAD": "KILL",
        "SCMP_ACT_TRACE": "TRACE",
        "SCMP_ACT_TRAP": "TRAP",
        "SCMP_ACT_LOG": "LOG",
        "SCMP_ACT_ERRNO": "ERRNO",
    }
    name = reverse.get(action, "ALLOW")
    if action == "SCMP_ACT_ERRNO" and errno is not None:
        return f"{name}({errno})"
    return name


def disassembler_to_json(dis):
    arch = dis.arch.rstrip('.') if dis.arch else 'X86_64'
    result = {
        "architectures": [f"SCMP_ARCH_{arch.upper()}"],
    }
    act, eno = _parse_action(dis.defaultAction)
    result["defaultAction"] = act
    if eno is not None:
        result["defaultErrnoRet"] = eno
    syscalls = []
    for name, info in dis.syscallSummary.items():
        if name == "total":
            continue
        a, e = _parse_action(info.get("action", "ALLOW"))
        entry = {
            "names": [name],
            "action": a,
            "args": []
        }
        if e is not None:
            entry["errnoRet"] = e
        syscalls.append(entry)
    result["syscalls"] = syscalls
    return result


def get_seccomp_profile_json(pid):
    """Return docker-style seccomp profile JSON for a process."""
    _, dis = get_seccomp_filters(pid)
    return disassembler_to_json(dis)


def get_default_seccomp_json():
    _, dis = get_default_seccomp()
    return disassembler_to_json(dis)


def json_to_summary(profile):
    """Convert a docker-style seccomp profile into a syscall summary dict."""
    summary = {}
    for sc in profile.get("syscalls", []):
        action = sc.get("action", "SCMP_ACT_ALLOW")
        errno = sc.get("errnoRet")
        act_str = _scmp_to_string(action, errno)
        for name in sc.get("names", []):
            summary[name] = {"action": act_str}
    return summary, _scmp_to_string(profile.get("defaultAction", "SCMP_ACT_ALLOW"), profile.get("defaultErrnoRet"))
