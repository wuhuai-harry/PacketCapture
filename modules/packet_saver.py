from pathlib import Path
import json
from datetime import datetime
from scapy.all import wrpcap

class PacketSaver:
    def __init__(self, config_path: Path = Path("config/output_config.json")):
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)

        self.output_dir = Path(self.config["output_dir"])
        self.output_dir.mkdir(exist_ok=True)
        self.max_pcap_bytes = self.config["max_pcap_size_mb"] * 1024 * 1024
        self.mask_password = self.config["mask_password"]

        self.current_pcap = None

    def _get_log_path(self):
        date_str = datetime.now().strftime("%Y%m%d")
        pattern = self.config["log_filename_pattern"].format(date=date_str)
        return self.output_dir / pattern

    def _get_new_pcap_path(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        pattern = self.config["pcap_filename_pattern"].format(timestamp=ts)
        return self.output_dir / pattern

    def save(self, packet, reason: str, info: dict):
        # 1. 写日志
        log_file = self._get_log_path()
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"捕获时间: {info['time']}\n")
            f.write(f"匹配原因: {reason}\n")
            if info['loginid']:
                f.write(f"用户名: {info['loginid']}\n")
            if info['password']:
                pwd = info['password']
                if self.mask_password and len(pwd) > 2:
                    masked = pwd[0] + '*' * (len(pwd)-2) + pwd[-1]
                else:
                    masked = '*' * len(pwd)
                f.write(f"密码(脱敏): {masked}\n")
                f.write(f"密码(原始): {pwd}\n")
            f.write(f"\n请求头:\n")
            for k, v in info['headers'].items():
                f.write(f"{k}: {v}\n")
            if info['body']:
                f.write(f"\n请求体(前500字符):\n{info['body'][:500]}\n")

        # 2. 写 PCAP
        if self.current_pcap is None or self.current_pcap.exists() and self.current_pcap.stat().st_size > self.max_pcap_bytes:
            self.current_pcap = self._get_new_pcap_path()

        wrpcap(str(self.current_pcap), [packet], append=self.current_pcap.exists())

        # 3. 控制台输出
        print(f"\n[{info['time']}] 捕获登录包")
        print(f"  匹配: {reason}")
        if info['loginid']: print(f"  用户名: {info['loginid']}")
        if info['password']:
            pwd = info['password']
            masked = pwd[0] + '*'*(len(pwd)-2) + (pwd[-1] if len(pwd)>1 else '')
            print(f"  密码: {masked}")