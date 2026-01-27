# modules/icmp_handler.py
import json
from pathlib import Path
from datetime import datetime
from scapy.all import wrpcap, IP, ICMP

class IcmpPacketHandler:
    def __init__(self, rules_path="config/icmp_capture_rules.json"):
        with open(rules_path, 'r', encoding='utf-8') as f:
            self.rules = json.load(f)

        self.target_types = set(self.rules.get("target_types", [0, 8]))
        self.target_ips = set(ip.strip() for ip in self.rules.get("target_ips", []))
        self.exclude_ips = set(ip.strip() for ip in self.rules.get("exclude_ips", []))

        output_cfg = self.rules["output"]
        self.output_dir = Path(output_cfg["log_dir"])
        self.output_dir.mkdir(exist_ok=True)
        self.log_pattern = output_cfg["log_filename_pattern"]
        self.pcap_pattern = output_cfg["pcap_filename_pattern"]
        self.max_pcap_bytes = output_cfg["max_pcap_size_mb"] * 1024 * 1024
        self.save_full = output_cfg.get("save_full_packet", True)

        self.current_pcap = None

    def _ip_match(self, src: str, dst: str) -> bool:
        # 如果 target_ips 为空，则不过滤
        if not self.target_ips:
            return True
        return (src in self.target_ips) or (dst in self.target_ips)

    def _ip_excluded(self, src: str, dst: str) -> bool:
        return (src in self.exclude_ips) or (dst in self.exclude_ips)

    def is_target_icmp(self, packet) -> tuple[bool, str]:
        if not (packet.haslayer(IP) and packet.haslayer(ICMP)):
            return False, "非IP/ICMP包"

        ip = packet[IP]
        icmp = packet[ICMP]

        if icmp.type not in self.target_types:
            return False, f"ICMP类型 {icmp.type} 不在目标列表"

        if not self._ip_match(ip.src, ip.dst):
            return False, f"IP不在目标列表: {ip.src} → {ip.dst}"

        if self._ip_excluded(ip.src, ip.dst):
            return False, f"IP被排除: {ip.src} → {ip.dst}"

        return True, "匹配ICMP规则"

    def extract_info(self, packet) -> dict:
        ip = packet[IP]
        icmp = packet[ICMP]
        return {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            'src_ip': ip.src,
            'dst_ip': ip.dst,
            'icmp_type': icmp.type,
            'icmp_code': icmp.code,
            'ttl': ip.ttl,
            'id': getattr(icmp, 'id', None),
            'seq': getattr(icmp, 'seq', None),
        }

    def _get_log_path(self):
        date_str = datetime.now().strftime("%Y%m%d")
        filename = self.log_pattern.format(date=date_str)
        return self.output_dir / filename

    def _get_pcap_path(self):
        if self.current_pcap is None or (self.current_pcap.exists() and self.current_pcap.stat().st_size > self.max_pcap_bytes):
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = self.pcap_pattern.format(timestamp=ts)
            self.current_pcap = self.output_dir / filename
        return self.current_pcap

    def save_packet(self, packet, reason: str, info: dict):
        # --- 日志 ---
        log_file = self._get_log_path()
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"时间: {info['timestamp']}\n")
            f.write(f"源IP: {info['src_ip']}\n")
            f.write(f"目的IP: {info['dst_ip']}\n")
            f.write(f"ICMP类型: {info['icmp_type']} (Code: {info['icmp_code']})\n")
            f.write(f"TTL: {info['ttl']}\n")
            if info['id'] is not None:
                f.write(f"ID: 0x{info['id']:04x}, 序列号: {info['seq']}\n")

        # --- PCAP ---
        if self.save_full:
            pcap_path = self._get_pcap_path()
            wrpcap(str(pcap_path), [packet], append=pcap_path.exists())

        # --- 控制台 ---
        direction = "请求" if info['icmp_type'] == 8 else "响应" if info['icmp_type'] == 0 else "其他"
        print(f"[{info['timestamp']}] ICMP {direction} | {info['src_ip']} → {info['dst_ip']}")