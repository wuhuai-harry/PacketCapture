# modules/dns_handler.py
import json
from pathlib import Path
from datetime import datetime
from scapy.all import DNS, IP, wrpcap

class DnsPacketHandler:
    def __init__(self, rules_path="config/dns_capture_rules.json", output_dir="login_captures"):
        with open(rules_path, 'r', encoding='utf-8') as f:
            self.rules = json.load(f)

        self.target_domains = [d.lower().rstrip('.') for d in self.rules.get("target_domains", [])]
        self.only_queries = self.rules.get("only_queries", False)
        self.only_responses = self.rules.get("only_responses", False)
        self.extract_answers = self.rules.get("extract_answers", True)

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.current_pcap = None
        self.max_pcap_bytes = 10 * 1024 * 1024  # 10MB

    def _domain_match(self, qname: str) -> bool:
        if not self.target_domains:
            return True
        q = qname.lower().rstrip('.')
        for pattern in self.target_domains:
            if pattern.startswith('*.'):
                suffix = pattern[2:]
                if q.endswith(suffix) or q == suffix:
                    return True
            elif q == pattern:
                return True
        return False

    def _get_qtype_name(self, qtype):
        types = {1: "A", 28: "AAAA", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 33: "SRV"}
        return types.get(qtype, f"TYPE{qtype}")

    def is_target_dns(self, packet):
        if not packet.haslayer(DNS) or not packet.haslayer(IP):
            return False, "非DNS或无IP"

        dns = packet[DNS]
        is_query = (dns.qr == 0)

        if self.only_queries and not is_query:
            return False, "跳过响应"
        if self.only_responses and is_query:
            return False, "跳过请求"

        if not dns.qd or not dns.qd.qname:
            return False, "无查询问题"

        try:
            qname = dns.qd.qname.decode('utf-8').rstrip('.')
        except:
            qname = str(dns.qd.qname).rstrip('.')

        if not self._domain_match(qname):
            return False, f"域名不匹配: {qname}"

        return True, "匹配DNS规则"

    def extract_info(self, packet):
        info = {
            'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'is_response': packet[DNS].qr == 1,
            'rcode': getattr(packet[DNS], 'rcode', 0),
            'query_name': '',
            'query_type': '',
            'answers': []
        }

        dns = packet[DNS]
        try:
            info['query_name'] = dns.qd.qname.decode('utf-8').rstrip('.')
            info['query_type'] = self._get_qtype_name(dns.qd.qtype)
        except:
            info['query_name'] = str(dns.qd.qname).rstrip('.')
            info['query_type'] = "UNKNOWN"

        if info['is_response'] and self.extract_answers and dns.an:
            answers = []
            for i in range(dns.ancount):
                an = dns.an[i]
                if an.type == 1:   # A
                    answers.append(f"A: {an.rdata}")
                elif an.type == 28: # AAAA
                    answers.append(f"AAAA: {an.rdata}")
                elif an.type == 5:  # CNAME
                    try:
                        cname = an.rdata.decode('utf-8').rstrip('.')
                    except:
                        cname = str(an.rdata).rstrip('.')
                    answers.append(f"CNAME: {cname}")
                else:
                    answers.append(f"TYPE{an.type}: {an.rdata}")
            info['answers'] = answers

        return info

    def save_packet(self, packet, reason: str, info: dict):
        # 日志
        log_file = self.output_dir / f"dns_capture_{datetime.now().strftime('%Y%m%d')}.log"
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"时间: {info['time']}\n")
            f.write(f"方向: {info['src_ip']} → {info['dst_ip']}\n")
            f.write(f"域名: {info['query_name']}\n")
            f.write(f"类型: {info['query_type']}\n")
            f.write(f"请求/响应: {'响应' if info['is_response'] else '请求'}\n")
            if info['is_response']:
                f.write(f"响应码: {info['rcode']}\n")
                if info['answers']:
                    f.write("回答:\n")
                    for a in info['answers']:
                        f.write(f"  - {a}\n")

        # PCAP
        if self.current_pcap is None or (self.current_pcap.exists() and self.current_pcap.stat().st_size > self.max_pcap_bytes):
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.current_pcap = self.output_dir / f"dns_packets_{ts}.pcap"

        wrpcap(str(self.current_pcap), [packet], append=self.current_pcap.exists())

        # 控制台
        print(f"\n[{info['time']}] DNS {'响应' if info['is_response'] else '请求'}")
        print(f"  域名: {info['query_name']}")
        print(f"  {info['src_ip']} → {info['dst_ip']}")