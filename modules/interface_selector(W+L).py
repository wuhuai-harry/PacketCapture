# modules/interface_selector.py
import json
import platform
from pathlib import Path          # 必须导入
from scapy.all import get_if_list, get_if_addr, IFACES

def load_preferred_interfaces(config_path: Path = Path("config/interfaces.json")):
    if config_path.exists():
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f).get("preferred", [])
    return []


def _get_linux_interfaces():
    """获取 Linux 网卡列表（含 IP）"""
    interfaces = []
    for name in get_if_list():
        try:
            ip = get_if_addr(name)
        except Exception:
            ip = "无IP"
        # 在 Linux 上，描述通常就是名称本身
        desc = name
        interfaces.append({
            'name': name,
            'description': desc,
            'ip': ip
        })
    return interfaces


def _get_windows_interfaces():
    """获取 Windows 网卡列表（需 Scapy 的 Windows 支持）"""
    try:
        from scapy.arch.windows import get_windows_if_list
        return get_windows_if_list()
    except ImportError:
        # 回退到通用方式（Windows 上可能信息较少）
        interfaces = []
        for name in get_if_list():
            try:
                ip = get_if_addr(name)
            except Exception:
                ip = "无IP"
            interfaces.append({
                'name': name,
                'description': name,
                'ip': ip
            })
        return interfaces


def select_interface():
    system = platform.system().lower()

    if system == "windows":
        interfaces = _get_windows_interfaces()
    else:
        # 包括 Linux, Darwin (macOS), FreeBSD 等
        interfaces = _get_linux_interfaces()

    if not interfaces:
        raise RuntimeError("未找到可用网卡")

    print("\n可用网卡:")
    for i, iface in enumerate(interfaces):
        name = iface.get('name', '未知')
        desc = iface.get('description', '无描述')
        ip = iface.get('ip', '无IP')
        print(f"[{i}] {name} | {desc} | IP: {ip}")

    # 尝试加载首选接口
    preferred = load_preferred_interfaces()
    if preferred:
        for idx, iface in enumerate(interfaces):
            if iface['name'] in preferred:
                print(f"\n自动选择首选接口: {iface['name']}")
                return iface['name']

    while True:
        try:
            choice = input("请选择网卡编号 (默认 0): ").strip()
            idx = int(choice) if choice else 0
            if 0 <= idx < len(interfaces):
                selected = interfaces[idx]['name']

                # 询问是否设为首选（可选）
                save_choice = input(f"是否将 '{selected}' 设为默认网卡? (y/n): ").strip().lower()
                if save_choice == 'y':
                    config_path = Path("config/interfaces.json")
                    config_path.parent.mkdir(exist_ok=True)
                    with open(config_path, 'w', encoding='utf-8') as f:
                        json.dump({"preferred": [selected]}, f, ensure_ascii=False, indent=2)
                    print(f"已保存默认网卡到 {config_path}")

                return selected
        except (ValueError, IndexError):
            print("无效输入，请输入有效编号")
