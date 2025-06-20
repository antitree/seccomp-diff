try: 
    from containerd.services.containers.v1 import containers_pb2, containers_pb2_grpc
    from containerd.services.namespaces.v1 import namespace_pb2, namespace_pb2_grpc  # For listing namespaces
    from containerd.services.tasks.v1 import tasks_pb2, tasks_pb2_grpc  # For listing tasks
except TypeError as e:
    print("Running in docker-only mode")
    ENV = "Docker"
except AttributeError as e:
    print("Running in docker-only mode")
    ENV = "Docker"
    
# from google.protobuf.any_pb2 import Any
# from opencontainers.runtime.specs.v1 import spec_pb2  # Assuming you have OCI spec proto definitions

import grpc
import argparse
import json
import os

class ContainerdConnectionError(Exception):
    """Raised when the agent cannot connect to containerd."""
    pass
ENV = "k8s"

DEFAULT_CAPABILITIES = [
    "CAP_AUDIT_WRITE",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_MKNOD",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_RAW",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_CHROOT",
]

def list_namespaces(containerd_socket):
    """
    List available namespaces in containerd.
    """
    channel = grpc.insecure_channel(f"unix://{containerd_socket}")
    namespace_client = namespace_pb2_grpc.NamespacesStub(channel)
    response = namespace_client.List(namespace_pb2.ListNamespacesRequest())
    return [ns.name for ns in response.namespaces]

def get_container_pid(containerd_socket, container_id, namespace="k8s.io"):
    """
    Fetch the OCI runtime spec for a container to access seccomp details.
    """
    channel = grpc.insecure_channel(f"unix://{containerd_socket}")
    client = tasks_pb2_grpc.TasksStub(channel)
    

    # Specify the namespace in the metadata
    metadata = (("containerd-namespace", namespace),)
    try:
        # TODO this isn't always consistent. Fix to make more reliable
        # this works at getting the pid sometimes but if the parrent process dies...
        # request = tasks_pb2.GetRequest(container_id=container_id)
        # response = client.Get(request, metadata=metadata)
        
        # This works at getting pids of running process
        response = client.ListPids(tasks_pb2.ListPidsRequest(container_id=container_id), metadata=metadata)
        if response:
            for process in response.processes:
                return process.pid
        
        #print(response)  
        
        # The OCI spec is returned as part of the response
        if response.process: 
            pid = response.process.pid
        else:
            pid = None
        return pid
    except grpc.RpcError as e:
        print(f"Error accessing PID for container {container_id}/{metadata}: {e}")
        return None

def get_container_image(containerd_socket, container_id, namespace="k8s.io"):
    channel = grpc.insecure_channel(f"unix://{containerd_socket}")
    client = containers_pb2_grpc.ContainersStub(channel)
    
    # Specify the namespace in the metadata
    metadata = (("containerd-namespace", namespace),)
    
    # Get container details
    try:
        response = client.Get(containers_pb2.GetContainerRequest(id=container_id), metadata=metadata)
        return response.container.image
    except grpc.RpcError as e:
        print(f"Error fetching details for container {container_id}: {e.details()}")
        return None

def get_containers(containerd_socket="/run/containerd/containerd.sock", namespace="k8s.io", with_seccomp=False):
    container_info = {}

    if not os.path.exists(containerd_socket):
        raise FileNotFoundError(f"containerd socket not found at {containerd_socket}")
    if not os.access(containerd_socket, os.R_OK | os.W_OK):
        raise PermissionError(f"permission denied accessing containerd socket at {containerd_socket}")

    channel = grpc.insecure_channel(f"unix://{containerd_socket}")
    client = containers_pb2_grpc.ContainersStub(channel)

    response = None
    try:
        metadata = (("containerd-namespace", namespace),)
        request = containers_pb2.ListContainersRequest()
        response = client.List(request, metadata=metadata)
    except grpc.RpcError as e:
        raise ContainerdConnectionError(f"failed to communicate with containerd: {e}") from e

    if response is None:
        return {}

    for container in response.containers:
        container_id = container.id
        name = container_id
        runtime = container.runtime.name
        
        labels, container_namespace, image = None, None, None
        # TODO Fix this to make it more accurate
        labels = container.labels
        if labels and "io.kubernetes.container.name" in labels:
            name = str(labels["io.kubernetes.container.name"])
        elif "io.kubernetes.pod.name" in labels: 
            name = str(labels["io.kubernetes.pod.name"])        
        
        if "io.kubernetes.pod.namespace" in labels: 
            container_namespace = str(labels["io.kubernetes.pod.namespace"])
            
        try: 
            pid = get_container_pid(containerd_socket, container_id, namespace=namespace)
            # TODO clean this up. Either it's a there or it's not
            # if not pid:
            #     print(f"Error: Containerd container {container_id} not found")
            #     break
        except Exception as e:
            print(f"UNCAUGHT EXCEPTION: NEEEDS INVESTIGATION: {e}")
            
            
        # get container image
        image = get_container_image(containerd_socket, container_id, namespace=namespace)
        
        seccomp_info = "unconfined"
        capabilities = []
        cmd = []
        if container.spec:
            spec_json = json.loads(container.spec.value)
            if "linux" in spec_json and "seccomp" in spec_json["linux"]:
                seccomp_info = spec_json["linux"]["seccomp"]
            if "process" in spec_json and "capabilities" in spec_json["process"] and "permitted" in spec_json["process"]["capabilities"]:
                capabilities = spec_json["process"]["capabilities"]["permitted"]
                if "args" in spec_json["process"]:
                    cmd = spec_json["process"]["args"]

        # CONFIG: Only return profiles with seccomp profiles
        if with_seccomp and not seccomp_info:
            continue

        container_info[name] = {
            "id": container_id,
            "name": name,
            "runtime": runtime,
            "cmd": "\n".join(cmd),
            "seccomp": json.dumps(seccomp_info),
            "image": image,
            "pid": pid,
            "labels": str(labels),
            "caps": "\n".join(capabilities),
            "namespace": container_namespace,
        }
    

    return container_info

def main():
    parser = argparse.ArgumentParser(description="List container runtime info from containerd.")
    parser.add_argument("--containerd-socket", default="/run/containerd/containerd.sock",
                        help="Path to the containerd socket.")
    parser.add_argument("--namespace", default="default",
                        help="Containerd namespace to query (e.g., 'k8s.io' for Kubernetes).")
    parser.add_argument("--with-seccomp", action="store_true", help="Include seccomp profile details.")
    parser.add_argument("--output", choices=["text", "json"], default="text", help="Output format.")
    parser.add_argument("--list-namespaces", action="store_true", help="List available containerd namespaces.")
    args = parser.parse_args()

    if args.list_namespaces:
        namespaces = list_namespaces(args.containerd_socket)
        print("Available namespaces:")
        for ns in namespaces:
            print(f"  - {ns}")
        return

    container_info = get_containers(
        containerd_socket=args.containerd_socket,
        namespace=args.namespace,
        with_seccomp=args.with_seccomp
    )

    if args.output == "json":
        print(json.dumps(container_info, indent=2))
    else:
        if container_info:
            print("Containers:")
            for container_id, details in container_info.items():
                print(f"Container ID: {container_id}, Runtime: {details['runtime']}, Seccomp: {details['seccomp']}")
        else:
            print("No containers found.")

if __name__ == "__main__":
    main()
