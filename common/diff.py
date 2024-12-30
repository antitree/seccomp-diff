from common.ptrace import get_seccomp_filters
from rich.console import Console
from common.output import CustomTable as Table
from rich import box
from rich.text import Text

def is_convertible_to_int(s):
    """Check if a string can be safely converted to an integer."""
    try:
        int(s)
        return True
    except ValueError:
        return False

def compare_seccomp_policies(container1, container2, full=False):
    try:
        # Extract SeccompSummary for both PIDs
        _, d1 = get_seccomp_filters(container1["pid"])
        _, d2 = get_seccomp_filters(container2["pid"])
        
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

        # Collect all unique syscall keys
        if container1["summary"] and container2["summary"]:
            all_syscalls = set(container1["summary"].keys()).union(set(container2["summary"].keys()))
        else:
            container1["summary"] = container1["summary"] if container1["summary"] else {}
            container2["summary"] = container2["summary"] if container2["summary"] else {}
            all_syscalls = set(container1["summary"]) if container1["summary"] else set(container2["summary"])


        # Compare syscalls and add rows to the table
        if not full:
            syscalls = sorted(
                (x for x in all_syscalls if not str(x).startswith("UnknownSyscall")),
                key=lambda x: (isinstance(x, str), x))
        else: 
            syscalls = sorted(all_syscalls, key=lambda x: (str(x)))
                              
        for syscall in syscalls:
            if syscall == "total":
                continue

            # Filter for resolved syscalls only
            # TODO standardize this into a config
            ONLYX86 = True
            if ONLYX86 and is_convertible_to_int(syscall):
                continue

            # Check for N/A cases
            count1 = container1["summary"].get(syscall, {"count": 0}).get("count") if syscall in container1["summary"] else None
            count2 = container2["summary"].get(syscall, {"count": 0}).get("count") if syscall in container2["summary"] else None
            action1 = container1["summary"].get(syscall, {"action": 0}).get("action") if syscall in container1["summary"] else None
            action2 = container2["summary"].get(syscall, {"action": 0}).get("action") if syscall in container2["summary"] else None
            

            if count1 is None or count2 is None:
                count1_display = f'[red]{da1}[DEFAULT]' if count1 is None else f'{action1}({count1})'
                count2_display = f'[red]{da2}' if count2 is None else f'{action2}({count2})'
                table.add_custom_row(syscall, str(count1_display), str(count2_display))

        # Add total instructions row
        container1["total"] = container1["summary"].get("total", {"count": 0}).get("count")
        container2["total"] = container2["summary"].get("total", {"count": 0}).get("count")
        table.add_custom_row("Total Instructions", str(container1["total"]), str(container2["total"]))

        if len(table.rows) <= 3 and container1["total"] == container2["total"]:
            console.print(Text("No seccomp filter differences were found between the two containers", justify="center"))
        
        return table

    except ValueError as e:
        print(f"An error occurred: {e}")