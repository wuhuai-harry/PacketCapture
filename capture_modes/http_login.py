# capture_modes/http_login.py
from modules.packet_filter import PacketFilter
from modules.packet_saver import PacketSaver
from modules.interface_selector import select_interface
from scapy.all import sniff
from datetime import datetime

class HttpLoginCapture:
    def run(self):
        print("\n" + "=" * 70)
        print("登录包精准抓取工具（HTTP 模式）")
        print("=" * 70)

        filter_engine = PacketFilter()
        saver = PacketSaver()
        interface = select_interface()

        packet_count = 0
        target_count = 0

        def packet_handler(packet):
            nonlocal packet_count, target_count
            if not hasattr(packet, 'load'):
                return
            packet_count += 1

            is_target, reason = filter_engine.is_login_packet(packet.load)
            if is_target:
                target_count += 1
                try:
                    raw_text = packet.load.decode('utf-8', errors='ignore')
                    info = filter_engine.extract_login_info(raw_text)
                    saver.save(packet, reason, info)
                except Exception as e:
                    print(f"处理包出错: {e}")

            if packet_count % 100 == 0:
                print(f"\r已处理 {packet_count} 包 | 捕获 {target_count} 目标包", end="", flush=True)

        print(f"\n开始在网卡 '{interface}' 上抓包...")
        print("过滤: tcp port 80/8080/443")
        print("按 Ctrl+C 停止\n")

        start_time = datetime.now()
        try:
            sniff(
                iface=interface,
                prn=packet_handler,
                store=0,
                filter="tcp port 80 or tcp port 8080 or tcp port 443"
            )
        except KeyboardInterrupt:
            pass
        finally:
            duration = datetime.now() - start_time
            print(f"\n\n抓包结束 | 总包: {packet_count} | 目标: {target_count} | 用时: {duration}")