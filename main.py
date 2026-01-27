#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import importlib
from modules.admin_check import require_admin

def main():
    require_admin()
    
    # 加载模式配置
    with open("config/capture_modes.json", "r", encoding="utf-8") as f:
        config = json.load(f)

    modes = config["modes"]
    print("=" * 70)
    print("多功能抓包工具")
    for i, mode in enumerate(modes, 1):
        print(f"{i}. {mode['name']}")
    print("=" * 70)

    try:
        choice = input("请选择模式: ").strip()
        idx = int(choice) - 1
        if not (0 <= idx < len(modes)):
            raise ValueError
        selected = modes[idx]
    except (ValueError, IndexError):
        print("无效选择，退出。")
        return

    # 动态加载并运行
    module = importlib.import_module(selected["module"])
    handler_class = getattr(module, selected["class"])
    handler = handler_class()
    handler.run()

    input("\n按 Enter 退出...")

if __name__ == "__main__":
    main()