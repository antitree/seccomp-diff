import json
import pytest
import docker
from common.ptrace import get_seccomp_filters

# Sample JSON data for testing
VALID_FILTERS = {
    "defaultAction": "SCMP_ACT_ALLOW",
    "syscalls": [
      {
        "name": "execve",
        "action": "SCMP_ACT_LOG",
        "args": [
          {
            "index": 0,
            "op": "SCMP_CMP_EQ",
            "value": 3 
          },
          {
            "index": 2,
            "op": "SCMP_CMP_EQ",
            "value": 4 
          }
        ]
     }]
  }

INVALID_FILTERS = {
    "defaultAction": "SCMP_ACT_ALLOW",
    "syscalls": [
      {
        "name": "execve",
        "action": "SCMP_ACT_LOG",
        "args": [
          {
            "index": 0,
            "op": "SCMP_CMP_EQ",
            "value": 3 
          },
          {
            "index": 2,
            "op": "SCMP_CMP_EQ",
            "value": 4 
          }
        ]
     }]
  }

@pytest.fixture(scope="module")
def valid_filters_file(tmp_path_factory):
    file = tmp_path_factory.mktemp("data") / "default.json"
    with open(file, "w") as f:
        json.dump(VALID_FILTERS, f)
    
    return str(file)

@pytest.fixture(scope="module")
def docker_container(valid_filters_file):
    client = docker.from_env()
    container = client.containers.run(
        "nginx",
        detach=True,
        remove=True,
        name="test_seccomp_1",
        security_opt=[f"seccomp={valid_filters_file}"]
    )
    yield container
    container.stop()

def test_valid_filters(docker_container, valid_filters_file):
    pid = docker_container.attrs['State']['Pid']

    # Call the function to retrieve filters
    filters, _ = get_seccomp_filters(pid=pid)

    # Load expected filters from the JSON file
    with open(valid_filters_file, "r") as f:
        expected_filters = json.load(f)["filters"]
        syscall_names = [entry["syscall"] for entry in expected_filters]

    # Assert results match
    assert filters == syscall_names

def test_invalid_syscall_handling(docker_container, valid_filters_file):
    # Mock an invalid seccomp file (manually modify it to include invalid syscall)
    with open(valid_filters_file, "r") as f:
        filters = json.load(f)
    filters["filters"].append({"syscall": "invalid_syscall", "action": "allow"})

    # Create a new invalid seccomp file
    invalid_file = valid_filters_file.with_name("invalid.json")
    with open(invalid_file, "w") as f:
        json.dump(filters, f)

    # Restart container with invalid seccomp profile
    docker_container.restart()

    pid = docker_container.attrs['State']['Pid']

    # Call the function to retrieve filters
    filters, _ = get_seccomp_filters(pid=pid)

    # Assert "invalid_syscall" is in the results (mocked scenario)
    assert "invalid_syscall" in filters

def test_empty_filters(docker_container, valid_filters_file):
    # Mock an empty seccomp file
    empty_filters = {"filters": []}
    empty_file = valid_filters_file.with_name("empty.json")
    with open(empty_file, "w") as f:
        json.dump(empty_filters, f)

    # Restart container with empty seccomp profile
    docker_container.restart()

    pid = docker_container.attrs['State']['Pid']

    # Call the function to retrieve filters
    filters, _ = get_seccomp_filters(pid=pid)

    # Assert filters list is empty
    assert filters == []
