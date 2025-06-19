import os
import requests
from typing import Iterable

AGENT_URLS = os.environ.get("AGENT_URLS", "").split(',') if os.environ.get("AGENT_URLS") else []


def list_all_containers():
    containers = []
    for url in AGENT_URLS:
        if not url:
            continue
        try:
            r = requests.get(f"{url}/list_containers", timeout=5)
            r.raise_for_status()
            data = r.json()
            for c in data.get('containers', []):
                c['agent'] = url
                containers.append(c)
        except Exception as e:
            print(f"Error contacting agent {url}: {e}")
    return containers


def fetch_profile(container):
    agent = container.get('agent')
    if agent:
        pid = container['pid']
        r = requests.get(f"{agent}/seccomp_profile/{pid}", timeout=10)
        r.raise_for_status()
        data = r.json()
        return data['profile'], data['full'], data.get('total', 0)
    else:
        from common.seccomp_json import get_seccomp_profile_json
        profile, full, dis = get_seccomp_profile_json(container['pid'])
        total = dis.syscallSummary.get('total', {}).get('count', 0)
        return profile, full, total
