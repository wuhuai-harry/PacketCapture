your_project/
│
├── main.py                          # 主程序入口（菜单 + 模式调度）
│
├── config/
│   ├── capture_modes.json           # 注册所有抓包模式（HTTP/DNS/ICMP...）
│   ├── http_login_rules.json        # HTTP 登录包规则（原 capture_login_rules.json）
│   ├── dns_capture_rules.json       # DNS 报文规则
│   └── icmp_capture_rules.json      # ICMP 报文规则
│
├── modules/
│   ├── __init__.py                  # （空文件，使 modules 成为包）
│   ├── interface_selector.py        # 网卡选择工具
│   ├── packet_saver.py              # 通用日志/PCAP 保存器（可选，复用）
│   │
│   ├── packet_filter.py             # HTTP 登录专用过滤器（含 is_login_packet + extract_login_info）
│   ├── dns_handler.py               # DNS 报文处理器
│   └── icmp_handler.py              # ICMP 报文处理器
│
├── capture_modes/
│   ├── __init__.py                  # （空文件，使 capture_modes 成为包）
│   ├── http_login.py                # HTTP 登录模式入口（调用 PacketFilter）
│   ├── dns_capture.py               # DNS 模式入口（调用 DnsHandler）
│   └── icmp_capture.py              # ICMP 模式入口（调用 IcmpHandler）
│
├── login_captures/                  # 自动创建的输出目录（所有模式共用）
│   ├── http_packets_20260124_1000.pcap
│   ├── dns_packets_20260124_1001.pcap
│   ├── icmp_packets_20260124_1002.pcap
│   ├── http_login_20260124.log
│   ├── dns_capture_20260124.log
│   └── icmp_capture_20260124.log
│
└── README.md                        # 项目说明（可选）
