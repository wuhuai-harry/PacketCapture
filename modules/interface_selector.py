from pathlib import Path
import json
from scapy.arch.windows import get_windows_if_list

def load_preferred_interfaces(config_path: Path = Path("config/interfaces.json")):
    if config_path.exists():
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f).get("preferred", [])
    return []

def select_interface():
    interfaces = get_windows_if_list()
    if not interfaces:
        raise RuntimeError("未找到可用网卡")

    print("\n可用网卡:")
    for i, iface in enumerate(interfaces):
        name = iface.get('name', '未知')
        desc = iface.get('description', '无描述')
        ip = iface.get('ip', '无IP')
        print(f"[{i}] {name} | {desc} | IP: {ip}")

    while True:
        try:
            choice = input("请选择网卡编号: ").strip()
            idx = int(choice) if choice else 0
            if 0 <= idx < len(interfaces):
                return interfaces[idx]['name']
        except (ValueError, IndexError):
            print("无效输入")