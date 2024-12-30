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
ENV = "k8s"

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
        request = tasks_pb2.GetRequest(container_id=container_id)
        response = client.Get(request, metadata=metadata)

        # The OCI spec is returned as part of the response
        if response.process: 
            pid = response.process.pid
        else:
            pid = None
        return pid
    except grpc.RpcError as e:
        print(f"Error accessing spec for container {container_id}: {e}")
        return None

def get_containers(containerd_socket="/run/containerd/containerd.sock", namespace="k8s.io", with_seccomp=False):
    container_info = {}

    # Connect to the containerd gRPC socket
    channel = grpc.insecure_channel(f"unix://{containerd_socket}")
    client = containers_pb2_grpc.ContainersStub(channel)

    try:
        # Specify the namespace in the metadata
        metadata = (("containerd-namespace", namespace),)
        request = containers_pb2.ListContainersRequest()
        response = client.List(request, metadata=metadata)
        
        

        for container in response.containers:
            container_id = container.id
            name = container_id
            runtime = container.runtime.name
            image = None
            
            labels = None
            # TODO Fix this to make it more accurate
            # try: 
            #     #labels = container.labels
            #     # if labels and "io.kubernetes.container.name" in labels:
            #     #     name = labels["io.kubernetes.container.name"]
            #     #     image = labels["io.kubernetes.container.image"]
            # except Exception as e:
            #     print(e)
            
            pid = get_container_pid(containerd_socket, container_id, namespace)
            if not pid:
                print("Error: Containerd container not found")
                break
            
            seccomp_info = "unknown"
            if container.spec:
                spec_json = json.loads(container.spec.value)
                if "linux" in spec_json and "seccomp" in spec_json["linux"]:
                    seccomp_info = spec_json["linux"]["seccomp"]
                if "process" in spec_json and "capabilities" in spec_json["process"]:
                    capabilities = spec_json["process"]["capabilities"]["permitted"]

            container_info[name] = {
                "id": container_id,
                "name": name,
                "runtime": runtime,
                "seccomp": str(seccomp_info),
                "image": image,
                "pid": pid,
                "labels": labels,
                "caps": "\n".join(capabilities),
            }
    except grpc.RpcError as e:
        print(f"Error accessing containerd: {e}")

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
