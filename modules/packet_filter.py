# modules/packet_filter.py
import re
import json as json_mod
from datetime import datetime
from pathlib import Path

class PacketFilter:
    def __init__(self, rules_path: Path = Path("config/http_login_rules.json")):
        with open(rules_path, 'r', encoding='utf-8') as f:
            self.rules = json_mod.load(f)

        self.target_paths = [p.strip().lower() for p in self.rules.get("target_paths", [])]
        self.methods = set(m.strip().upper() for m in self.rules.get("http_methods", ["POST"]))
        self.login_fields = [f.strip().lower() for f in self.rules.get("login_fields", ["username", "password"])]
        self.content_types = [ct.strip().lower() for ct in self.rules.get("content_types", [
            "application/x-www-form-urlencoded",
            "application/json"
        ])]

    def is_login_packet(self, packet_data: bytes) -> tuple[bool, str]:
        try:
            text = packet_data.decode('utf-8', errors='ignore')
        except Exception:
            text = packet_data.decode('latin-1', errors='ignore')

        text_lower = text.lower()

        # 1. 尝试解析 HTTP 请求行（方法 + 路径）
        request_line_match = False
        if '\r\n' in text:
            first_line = text.split('\r\n', 1)[0]
            if any(first_line.startswith(method) for method in self.methods):
                for path in self.target_paths:
                    if path in first_line.lower():
                        request_line_match = True
                        break

        # 2. 检查是否包含登录字段（全文或 body）
        has_login_field = False
        body_text = ""
        if '\r\n\r\n' in text:
            _, body = text.split('\r\n\r\n', 1)
            body_text = body
        else:
            body_text = text  # 可能是 chunked 或不完整包

        body_lower = body_text.lower()
        if any(field in body_lower for field in self.login_fields):
            has_login_field = True

        # 3. 检查 Content-Type（如果配置了）
        content_type_match = False
        if self.content_types:
            if any(ct in text_lower for ct in self.content_types):
                content_type_match = True
        else:
            content_type_match = True  # 未配置则不限制

        # 判定逻辑：
        # - 如果指定了 target_paths，则要求路径匹配 + (字段 or Content-Type)
        # - 如果未指定 target_paths，则只要字段 + Content-Type 匹配即可
        if self.target_paths:
            if request_line_match and (has_login_field or content_type_match):
                return True, "匹配请求路径且含登录特征"
        else:
            if has_login_field and content_type_match:
                return True, "含登录字段且符合内容类型"

        return False, "非目标包"

    def extract_login_info(self, raw_text: str) -> dict:

        info = {
            'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            'loginid': None,
            'password': None,
            'headers': {},
            'body': ''
        }

        try:
            if '\r\n\r\n' in raw_text:
                headers_part, body = raw_text.split('\r\n\r\n', 1)
                info['body'] = body.strip()
            else:
                headers_part = raw_text.split('\r\n\r\n')[0] if '\r\n\r\n' in raw_text else raw_text
                info['body'] = ""

            # 解析请求头
            lines = headers_part.split('\r\n')
            if lines:
                info['headers']['Request-Line'] = lines[0]
                for line in lines[1:]:
                    if ': ' in line:
                        key, val = line.split(': ', 1)
                        info['headers'][key] = val

            # 判断是否为 JSON
            content_type = info['headers'].get('Content-Type', '').lower()
            is_json = any('application/json' in ct for ct in self.content_types) and 'application/json' in content_type

            body_text = info['body']
            body_lower = body_text.lower()

            # 尝试 JSON 解析（仅当明确是 JSON 时）
            json_data = None
            if is_json:
                try:
                    json_data = json_mod.loads(body_text)
                except json_mod.JSONDecodeError:
                    pass  # 回退到正则

            # 提取每个字段
            for field in self.login_fields:
                field_lower = field.lower()
                found_val = None

                # 1. 优先从 JSON 提取
                if json_data is not None:
                    if isinstance(json_data, dict):
                        # 支持大小写不敏感匹配（但保留原始 key）
                        for k, v in json_data.items():
                            if k.lower() == field_lower:
                                found_val = str(v) if v is not None else ""
                                break

                # 2. 回退到正则（表单或混合）
                if found_val is None:
                    # 改进正则：匹配 username=admin, "password":"123", password='456', email: test@ex.com
                    escaped_field = re.escape(field)
                    pattern = rf'["\']?{escaped_field}["\']?\s*[:=]\s*["\']?([^&\s"\'\r\n,}}]+)'
                    match = re.search(pattern, body_lower, re.IGNORECASE)
                    if match:
                        found_val = match.group(1)

                # 3. 赋值到 loginid / password
                if found_val is not None:
                    # 清理可能的尾部符号（如逗号、引号残留）
                    found_val = found_val.rstrip(',}"\'')
                    LOGINID_FIELDS = {'loginid', 'username', 'user', 'email', 'mobile', 'userid', 'loginname', 'account', 'name', 'id'}
                    PASSWORD_FIELDS = {'userpassword', 'password', 'pass', 'secret', 'pwd', 'passwd'}
                    if field_lower in LOGINID_FIELDS:
                        info['loginid'] = found_val
                    elif field_lower in PASSWORD_FIELDS:
                        info['password'] = found_val

        except Exception as e:
            print(f"[PacketFilter] 提取失败: {e}")

        return info