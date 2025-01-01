from common.ptrace import get_seccomp_filters
from common.output import CustomTable as Table
from lib.syscalls.x86_64 import syscall_dict as SYSCALLS
from rich.console import Console
from rich import box
from rich.text import Text

def is_convertible_to_int(s):
    """Check if a string can be safely converted to an integer."""
    try:
        int(s)
        return True
    except ValueError:
        return False

dangerous_syscalls = [
    "acct", "add_key", "bpf", "clock_adjtime", "clone", "create_module",
    "delete_module", "finit_module", "get_kernel_syms", "get_mempolicy",
    "init_module", "ioperm", "iopl", "kcmp", "kexec_file_load", "kexec_load",
    "keyctl", "lookup_dcookie", "mbind", "mount", "move_pages", "nfsservctl",
    "open_by_handle_at", "perf_event_open", "personality", "pivot_root",
    "process_vm_readv", "process_vm_writev", "ptrace", "query_module",
    "quotactl", "reboot", "request_key", "set_mempolicy", "setns",
    "settimeofday", "stime", "swapon", "swapoff", "sysfs", "_sysctl", "umount",
    "umount2", "unshare", "uselib", "userfaultfd", "ustat", "vm86", "vm86old"
]

def get_seccomp_policy(container1):
    full1, d1 = get_seccomp_filters(container1["pid"])
    if d1: 
        container1["summary"] = d1.syscallSummary
    else:
        container1["summary"] = {}

    da1 = d1.defaultAction

    console = Console()
    table = Table(show_header=True, show_lines=True, box=box.HEAVY_EDGE, style="green", pad_edge=False)
    table.add_column(header="Container", justify="left", min_width=20)
    table.add_column(header=container1["name"], justify="left", max_width=20, overflow=None)
    table.add_column(header=container2["name"], justify="left", max_width=20, overflow=None)

    # Add Seccomp and Capabilities Information
    table.add_custom_row("[b]seccomp", container1["seccomp"])
    table.add_custom_row("[b]caps", container1["caps"], end_section=True)

    # Iterate through the global SYSCALLS dict
    for syscall_num, syscall_info in SYSCALLS.items():
        syscall_name = syscall_info[1]

        # Determine effective policy for container1
        if syscall_name in container1["summary"]:
            action1 = container1["summary"][syscall_name].get("action", da1)
            count1 = container1["summary"][syscall_name].get("count", 0)
            effective_policy1 = f"{action1}"
        else:
            effective_policy1 = f"{da1}"

        table.add_custom_row(syscall_name, effective_policy1)

    # Add total instructions row
    container1["total"] = container1["summary"].get("total", {"count": 0}).get("count")
    table.add_custom_row("Total Instructions", str(container1["total"]))
    
    return table, full1

def compare_seccomp_policies(container1, container2, full=False):
    try:
        # Extract SeccompSummary for both PIDs
        full1, d1 = get_seccomp_filters(container1["pid"])
        full2, d2 = get_seccomp_filters(container2["pid"])
        
        

        if d1: 
            container1["summary"] = d1.syscallSummary
        else:
            container1["summary"] = {}

        if d2:
            container2["summary"] = d2.syscallSummary
        else:
            container2["summary"] = {}

        da1 = d1.defaultAction
        da2 = d2.defaultAction

        console = Console()
        table = Table(show_header=True, show_lines=True, box=box.HEAVY_EDGE, style="green", pad_edge=False)
        table.add_column(header="Container", justify="left", min_width=20)
        table.add_column(header=container1["name"], justify="left", max_width=20, overflow=None)
        table.add_column(header=container2["name"], justify="left", max_width=20, overflow=None)

        # Add Seccomp and Capabilities Information
        table.add_custom_row("[b]seccomp", container1["seccomp"], container2["seccomp"])
        table.add_custom_row("[b]caps", container1["caps"], container2["caps"], end_section=True)

        # Iterate through the global SYSCALLS dict
        for syscall_num, syscall_info in SYSCALLS.items():
            syscall_name = syscall_info[1]

            # Determine effective policy for container1
            if syscall_name in container1["summary"]:
                action1 = container1["summary"][syscall_name].get("action", da1)
                count1 = container1["summary"][syscall_name].get("count", 0)
                effective_policy1 = f"{action1}"
            else:
                effective_policy1 = f"{da1}"

            # Determine effective policy for container2
            if syscall_name in container2["summary"]:
                action2 = container2["summary"][syscall_name].get("action", da2)
                count2 = container2["summary"][syscall_name].get("count", 0)
                effective_policy2 = f"{action2}"
            else:
                effective_policy2 = f"{da2}"

            # Compare effective policies
            if effective_policy1 == effective_policy2:
                continue  # Skip identical policies

            table.add_custom_row(syscall_name, effective_policy1, effective_policy2)

        # Add total instructions row
        container1["total"] = container1["summary"].get("total", {"count": 0}).get("count")
        container2["total"] = container2["summary"].get("total", {"count": 0}).get("count")
        table.add_custom_row("Total Instructions", str(container1["total"]), str(container2["total"]))

        if len(table.rows) <= 3 and container1["total"] == container2["total"]:
            console.print(Text("No seccomp filter differences were found between the two containers", justify="center"))
        
        return table, full1, full2

    except ValueError as e:
        print(f"An error occurred: {e}")
