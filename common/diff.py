import json
from common.ptrace import get_seccomp_profile, get_default_seccomp
from common.output import CustomTable as Table
from lib.syscalls.x86_64 import syscall_dict as SYSCALLS
from rich.console import Console
from rich import box
from rich.text import Text
from rich.style import Style


DANGEROUS_SYSCALLS = ["acct", "add_key", "bpf", "clock_adjtime", "clone", "create_module",
        "delete_module", "finit_module", "get_kernel_syms", "get_mempolicy",
        "init_module", "ioperm", "iopl", "kcmp", "kexec_file_load", "kexec_load",
        "keyctl", "lookup_dcookie", "mbind", "mount", "move_pages", "nfsservctl",
        "open_by_handle_at", "perf_event_open", "personality", "pivot_root",
        "process_vm_readv", "process_vm_writev", "ptrace", "query_module",
        "quotactl", "reboot", "request_key", "set_mempolicy", "setns",
        "settimeofday", "stime", "swapon", "swapoff", "sysfs", "_sysctl", "umount",
        "umount2", "unshare", "uselib", "userfaultfd", "ustat", "vm86", "vm86old"]

def reduce_action(action):
    ALLOW = ["ALLOW", action, "permissive"]
    DENY = ["DENY", action, "restrictive"]
    CONDITION = ["CONDITION", action, "restrictive"]
    UNKNOWN = ["ERROR-NOT-FOUND", action, "permissive"]
    ACTION_MAP = {
        "ALLOW": ALLOW,
        "ERRNO": DENY, 
        "ALLOW/ERRORNO": CONDITION,
        "N/A": ALLOW,
        "LOG": ALLOW,
        "KILL": DENY,
        "TRACE": CONDITION,
        "TRAP": CONDITION,
        "CONDITION": CONDITION,
        "Unknown": UNKNOWN,
    }
    # Check error numbers
    if action.startswith("ERRNO"):
        return DENY
    elif "/" in action and action != "N/A":
        return CONDITION
    return ACTION_MAP.get(action, [f"FERROR MAPPING EFFECTIVE PERMISSIONS {action}"])
    

def is_convertible_to_int(s):
    """Check if a string can be safely converted to an integer."""
    try:
        int(s)
        return True
    except ValueError:
        return False


def profile_to_summary(profile):
    """Convert Docker-style seccomp JSON profile into summary mapping."""
    summary = {}
    if not profile:
        return summary
    for rule in profile.get("syscalls", []):
        names = rule.get("names") or []
        action = rule.get("action", "SCMP_ACT_ALLOW")
        for n in names:
            summary[n] = {"action": action}
    return summary

   

def compare_seccomp_policies(container1, container2, reduce=True, only_diff=True, only_dangerous=False):
    """Compare the seccomp policies of two containers and return a detailed table."""

    danger_style = Style(color="red", blink=True, bold=True)

    try:
        if "profile" not in container1:
            container1["profile"] = get_seccomp_profile(container1["pid"])
        if container2 == "default":
            container2 = {
                "pid": None,
                "name": "RuntimeDefault",
                "seccomp": "",
                "caps": "",
                "profile": get_default_seccomp(),
            }
        elif "profile" not in container2:
            container2["profile"] = get_seccomp_profile(container2["pid"])

        container1["summary"] = profile_to_summary(container1["profile"])
        container2["summary"] = profile_to_summary(container2["profile"])

        default_action1 = container1["profile"].get("defaultAction", "SCMP_ACT_ALLOW")
        default_action2 = container2["profile"].get("defaultAction", "SCMP_ACT_ALLOW")

        console = Console()
        table = Table(show_header=True, show_lines=True, box=box.HEAVY_EDGE, style="green", pad_edge=False)
        table.add_column(header="Container:", justify="left", min_width=20)
        table.add_column(header=f"{container1['name']}", justify="left", min_width=20)
        table.add_column(header=f"{container2['name']}", justify="left", min_width=20)

        table.add_custom_row("[b]seccomp", container1.get("seccomp", ""), container2.get("seccomp", ""))
        table.add_custom_row("[b]total", str(len(container1["summary"])), str(len(container2["summary"])))

        cap1 = container1.get("capabilities", [])
        cap2 = container2.get("capabilities", [])
        cap1 = set(cap1) if cap1 else set()
        cap2 = set(cap2) if cap2 else set()
        if only_diff:
            cap1 = cap1.difference(cap2)
            cap2 = cap2.difference(cap1)

        table.add_custom_row("[b]caps", "\n".join(cap1), "\n".join(cap2))
        table.add_custom_row("[b]pid", str(container1.get("pid")), str(container2.get("pid")), end_section=True)
        table.add_custom_row("[b]system calls", "", "")

        for syscall_num, syscall_info in SYSCALLS.items():
            syscall_name = syscall_info[1]

            if only_dangerous and syscall_name not in DANGEROUS_SYSCALLS:
                continue

            action1 = container1["summary"].get(syscall_name, {}).get("action", default_action1)
            action2 = container2["summary"].get(syscall_name, {}).get("action", default_action2)

            if reduce:
                action1 = reduce_action(action1.replace("SCMP_ACT_", ""))[0]
                action2 = reduce_action(action2.replace("SCMP_ACT_", ""))[0]

            if only_diff and action1 == action2:
                continue

            if syscall_name in DANGEROUS_SYSCALLS:
                syscall_name = f":warning:{syscall_name}"

            table.add_custom_row(syscall_name, action1, action2)

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

    if len(table.rows) <= 3:
        console.print(Text("No seccomp filter differences were found between the two containers", justify="center"))

    return table

    
    
    
