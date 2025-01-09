import json
from common.ptrace import get_seccomp_filters, get_default_seccomp
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

   

def compare_seccomp_policies(container1, container2, reduce=True, only_diff=True, only_dangerous=False):
    """Compare the seccomp policies of two containers and return a detailed table."""
    
    danger_style = Style(color="red", blink=True, bold=True)
    
    try:
        full1, d1 = get_seccomp_filters(container1["pid"])
        if container2 == "default":
            full2, d2 = get_default_seccomp()
            container2 = {
                "pid": None, 
                "name": "RuntimeDefault",
                "seccomp": "", 
                "caps": "",
                }
        else: 
            full2, d2 = get_seccomp_filters(container2["pid"])

        if d1:
            container1["summary"] = d1.syscallSummary
        else:
            container1["summary"] = {}

        if d2:
            container2["summary"] = d2.syscallSummary
        else:
            container2["summary"] = {}

        default_action1 = d1.defaultAction if d1 else "unknown"
        default_action2 = d2.defaultAction if d2 else "unknown"

        console = Console()
        table = Table(show_header=True, show_lines=True, box=box.HEAVY_EDGE, style="green", pad_edge=False)
        table.add_column(header="Container:", justify="left", min_width=20)
        table.add_column(header=f"{container1['name']}", justify="left", min_width=20)
        table.add_column(header=f"{container2['name']}", justify="left", min_width=20)
        
        # Add Seccomp and Capabilities Information
        table.add_custom_row("[b]seccomp", container1["seccomp"], container2["seccomp"])
        table.add_custom_row("[b]caps", container1["caps"], container2["caps"], end_section=True)
        table.add_custom_row("System Calls", "", "")
        

        # Iterate through all syscalls in SYSCALLS
        for syscall_num, syscall_info in SYSCALLS.items():
            syscall_name = syscall_info[1]
            
            if only_dangerous and not syscall_name in DANGEROUS_SYSCALLS:
                continue
            
            

            # Get the action for container1
            if syscall_name in container1["summary"]:
                action1 = container1["summary"][syscall_name].get("action", default_action1)
            else:
                action1 = default_action1

            # Get the action for container2
            if syscall_name in container2["summary"]:
                action2 = container2["summary"][syscall_name].get("action", default_action2)
            else:
                action2 = default_action2
                    
            # Reduce the action to an effecctive action of allow or deny
            if reduce:
                action1 = reduce_action(action1)[0]
                action2 = reduce_action(action2)[0]

            # Skip identical policies if only_diff is True
            if only_diff and action1 == action2:
                continue
            
            if syscall_name in DANGEROUS_SYSCALLS:
                syscall_name = f":warning:{syscall_name}"
            
            # Add row to table
            table.add_custom_row(syscall_name, action1, action2)
        
    except Exception as e:
        print(f"An error occurred: {e}")
        return None, None, None
            
    # Add total instructions row
    container1["total"] = container1["summary"].get("total", {"count": 0}).get("count")
    container2["total"] = container2["summary"].get("total", {"count": 0}).get("count")
    table.add_custom_row("Total Instructions", str(container1["total"]), str(container2["total"]))
    if len(table.rows) <= 3 and container1["total"] == container2["total"]:
        console.print(Text("No seccomp filter differences were found between the two containers", justify="center"))

    return table, full1, full2

    
    
    
