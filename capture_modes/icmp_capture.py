# capture_modes/icmp_capture.py
from modules.interface_selector import select_interface
from modules.icmp_handler import IcmpPacketHandler
from scapy.all import sniff

class IcmpCapture:
    def run(self):
        interface = select_interface()
        icmp_handler = IcmpPacketHandler()

        def callback(packet):
            is_target, reason = icmp_handler.is_target_icmp(packet)
            if is_target:
                info = icmp_handler.extract_info(packet)
                icmp_handler.save_packet(packet, reason, info)

        print(f"\n开始抓取 ICMP 报文...")
        print("按 Ctrl+C 停止\n")
        try:
            sniff(iface=interface, prn=callback, store=0, filter="icmp")
        except KeyboardInterrupt:
            pass
        print("\nICMP 抓包结束。")