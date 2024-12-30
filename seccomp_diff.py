import common.docker as docker
import common.containerd as containerd
from common.diff import compare_seccomp_policies
from common.output import CustomTable as Table

from rich.console import Console
from rich import box
from rich.text import Text
import argparse

ENV = "Docker" # Sets the default environment to be docker for local testing

def display_shmoocon_intro():
    """Display introductory ASCII art and information about the Shmoocon project."""
    console = Console()

    ascii_art = [
        " ▗▄▄▖▗▖ ▗▖▗▖  ▗▖ ▗▄▖  ▗▄▖  ▗▄▄▖ ▗▄▖ ▗▖  ▗▖",
        "▐▌   ▐▌ ▐▌▐▛▚▞▜▌▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌ ▐▌▐▛▚▖▐▌",
        " ▝▀▚▖▐▛▀▜▌▐▌  ▐▌▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌ ▐▌▐▌ ▝▜▌",
        "▗▄▄▞▘▐▌ ▐▌▐▌  ▐▌▝▚▄▞▘▝▚▄▞▘▝▚▄▄▖▝▚▄▞▘▐▌  ▐▌",
        "",
        "                     ▄▄▄▄ ▄▀▀▚▖▄▄▄▄ ▄▄▄▄  ",
        "                        █ █  ▐▌   █ █     ",
        "                     █▀▀▀ █  ▐▌█▀▀▀ ▀▀▀█  ",
        "                     █▄▄▄ ▀▄▄▞▘█▄▄▄ ▄▄▄█  ",
        "",
        "                  SHMOOCON 2025",
        "             >>>  Commencement  <<<",
        "",
        "      Authored by: Jay Beale & Mark Manning",
        "",
        "=====================================================",
        "                 Docker seccomp differ",
        "  Choose 2 of the provided running containers to diff",
        "  the seccomp profiles that are applied. Try adding",
        "  different capabilities to your containers and watch",
        "  what happens. Happy Shmoocon!",
        "====================================================="
    ]

    for line in ascii_art:
        console.print(Text(line, justify="center"))



def main():
    """Main entry point for comparing seccomp policies of Docker containers."""
    display_shmoocon_intro()
    
    parser = argparse.ArgumentParser(description="Get container information from Docker or Kubernetes.")
    parser.add_argument("-k", "--kubernetes", action="store_true", help="Use Kubernetes to fetch container info.")
    parser.add_argument("-d", "--docker", action="store_true", help="Use Docker to fetch container info (default).")
    args = parser.parse_args()
    

    if args.kubernetes:
        ENV = "k8s"
    else:
        ENV = "Docker"

    console = Console()
    table = Table(show_header=True, show_lines=True, box=box.HEAVY_EDGE, style="green", pad_edge=False)
    table.add_column(header="Container", justify="left", min_width=20)
    table.add_column(header="PID", justify="left", min_width=0)
    table.add_column(header="Seccomp Profile", justify="left", max_width=40)
    table.add_column(header="Added Capabilities", justify="left", min_width=0, max_width=20, no_wrap=True)
    
    try:
        # Get container PIDs
        # check if it's docker or k8s environment
        if ENV == "Docker":
            #container_pids = list_docker_pids.get_container_pids()
            containers = docker.get_containers()
            
            # Sort containers by PID in descending order
            containers = dict(sorted(containers.items(), key=lambda item: item[1]["pid"], reverse=True))
                
        elif ENV == "k8s":
            containers = containerd.get_containers()
            
        for name, values in containers.items():
            table.add_custom_row(name, str(values["pid"]), values["seccomp"], str(values["caps"]))
        console.print(table)

        # Prompt user for container names
        container1 = input(f"Enter the first container name [{list(containers.keys())[0]}]: ") or list(containers.keys())[0]
        container2 = input(f"Enter the second container name [{list(containers.keys())[1]}]: ") or list(containers.keys())[1]
        if container1 == container2:
            raise ValueError("Cannot compare a container to itself")

        # Compare seccomp policies
        table, _, _ = compare_seccomp_policies(containers[container1], containers[container2])
        console.print(table)

    except ValueError as e:
        print(f"Invalid container names: {e}")
    except KeyError as e:
        print(f"Cannot find container with that name: {e}")

if __name__ == "__main__":
    main()

