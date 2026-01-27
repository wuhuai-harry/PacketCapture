# capture_modes/dns_capture.py
from modules.interface_selector import select_interface
from modules.dns_handler import DnsPacketHandler
from scapy.all import sniff

class DnsCapture:
    def run(self):
        interface = select_interface()
        dns_handler = DnsPacketHandler(output_dir="login_captures")

        def dns_callback(packet):
            is_target, reason = dns_handler.is_target_dns(packet)
            if is_target:
                info = dns_handler.extract_info(packet)
                dns_handler.save_packet(packet, reason, info)

        print(f"\n开始抓取 DNS 报文 (端口 53)...")
        print("按 Ctrl+C 停止\n")
        try:
            sniff(iface=interface, prn=dns_callback, store=0, filter="udp port 53 or tcp port 53")
        except KeyboardInterrupt:
            pass
        print("\nDNS 抓包结束。")