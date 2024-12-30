#!/bin/bash

# Bash script to run the seccomp inspector container

# Check if a PID was provided
if [ -z "$1" ]; then
    echo "No PID provided. Please provide a PID to inspect."
    echo "Here are some example commands to list running processes and their PIDs:"
    echo "  ps aux"  # Lists all running processes with their PIDs
    echo "  pstree -p"  # Visualizes the process tree with PIDs
    echo "  top"  # Interactive view of running processes with PIDs
    exit 1
fi

PID=$1

# Check if the provided PID exists
if [ ! -e "/proc/$PID" ]; then
    echo "Error: PID $PID does not exist on the host."
    exit 1
fi

# Define the image name
IMAGE_NAME="seccomp-dumper"

# Run the Docker container with necessary permissions and arguments
docker run --rm -it \
  --pid=host \
  --privileged \
  --security-opt seccomp=unconfined \
  --cap-add=SYS_PTRACE \
  -v /proc:/host/proc:ro \
  $IMAGE_NAME \
  --summary $PID

