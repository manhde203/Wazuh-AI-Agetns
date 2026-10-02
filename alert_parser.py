"""
alert_parser.py
---------------
Chuẩn hóa alert Wazuh + các bộ lọc nhanh (KHÔNG dùng LLM).

Tách riêng khỏi main.py để pipeline, bộ gom nhóm và kiểm thử cùng dùng chung.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone

logger = logging.getLogger("soc_agent.parser")

# ----------------------------------------------------------------------
# Hằng số
# ----------------------------------------------------------------------
# Nhóm rule không bao giờ là tấn công (nhiễu tuân thủ/audit)
SKIP_GROUPS = {
    "gdpr", "hipaa", "pci_dss", "nist_800_53", "tsc",
    "cis", "sca", "benchmark", "audit", "policy_monitoring",
}

# Nhóm rule của từng lần đăng nhập thất bại (level thấp, 3-5). Phải kéo cả
# những alert này từ Indexer thì mới đếm được brute-force (xem wazuh_client).
BRUTE_FORCE_QUERY_GROUPS = [
    "authentication_failed",
    "authentication_failures",
    "invalid_login",
]

# Rule "tổng hợp": chính Wazuh đã tự tương quan nhiều lần thất bại → là bằng
# chứng brute-force mạnh. HÃY ĐỐI CHIẾU với ruleset trên Wazuh Manager của bạn
# (ví dụ /var/ossec/ruleset/rules/0095-sshd_rules.xml) vì ID có thể khác
# giữa các phiên bản.
COMPOSITE_RULE_IDS = {"2502", "5551", "5712", "5720", "5758", "5763"}
COMPOSITE_MARKERS = (
    "brute force",
    "multiple failed",
    "multiple authentication failures",
    "more than once",
)

BRUTE_FORCE_MARKERS = (
    "brute force",
    "multiple failed login",
    "failed login",
    "failed password",
    "authentication failure",
    "authentication_failure",
    "authentication_failed",
    "invalid user",
    "invalid_login",
    "non existent user",
    "missed the password",
)

_CTRL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


# ----------------------------------------------------------------------
# Tiện ích
# ----------------------------------------------------------------------
def _dig(data, *path):
    """Lấy giá trị lồng nhau an toàn: _dig(d,'win','eventdata','ipAddress')."""
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def sanitize_text(text, limit: int = 220) -> str:
    """
    Làm sạch dữ liệu log trước khi đưa vào prompt (giảm prompt injection):
    bỏ ký tự điều khiển, gộp khoảng trắng, cắt độ dài, vô hiệu dấu phân cách
    <<<LOG_DATA / LOG_DATA>>> mà prompt dùng để bao dữ liệu không tin cậy.
    """
    s = _CTRL_CHARS.sub(" ", str(text))
    s = " ".join(s.split())
    s = s.replace("LOG_DATA", "LOG-DATA")
    return s[:limit]


def alert_event_time(parsed: dict) -> float:
    """
    Thời điểm sự kiện (epoch, UTC). Wazuh ghi dạng '2026-05-01T10:00:00.123+0000'
    (không có dấu ':' ở múi giờ) → Python 3.10 không parse được nếu không sửa.
    """
    ts = parsed.get("timestamp", "")
    try:
        value = str(ts).replace("Z", "+00:00")
        value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value)
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).timestamp()
    except (TypeError, ValueError):
        return time.time()


# ----------------------------------------------------------------------
# Trích xuất IP & chuẩn hóa alert
# ----------------------------------------------------------------------
_IGNORED_IPS = ("", "0.0.0.0", "127.0.0.1", "::1", "::")


def extract_attacker_ip(alert: dict) -> str:
    """Trích IP nguồn từ mọi đường dẫn decoder đã biết của Wazuh."""
    data = alert.get("data") or {}
    full_log = alert.get("full_log", "") or ""

    candidates = [
        data.get("srcip"),
        data.get("src_ip"),
        data.get("remote_addr"),
        _dig(data, "win", "eventdata", "ipAddress"),
        _dig(data, "win", "eventdata", "sourceAddress"),
        _dig(data, "win", "eventdata", "callerIp"),
        _dig(data, "audit", "remote_addr"),
        _dig(data, "audit", "address"),
        _dig(data, "netflow", "src_addr"),
        _dig(data, "netflow", "source_ip"),
        _dig(data, "alert", "src_ip"),
        _dig(data, "src", "ip"),
        data.get("source_ip"),
        data.get("attacker_ip"),
        data.get("client_ip"),
        data.get("ip_address"),
    ]
    for ip in candidates:
        if ip and isinstance(ip, str) and ip not in _IGNORED_IPS:
            return ip

    if full_log:
        patterns = [
            r"from\s+((?:\d{1,3}\.){3}\d{1,3})",
            r"src[=:\s]+((?:\d{1,3}\.){3}\d{1,3})",
            r"client[=:\s]+((?:\d{1,3}\.){3}\d{1,3})",
            r"source[=:\s]+((?:\d{1,3}\.){3}\d{1,3})",
            r"rhost[=:\s]+((?:\d{1,3}\.){3}\d{1,3})",
        ]
        for pattern in patterns:
            match = re.search(pattern, full_log, re.IGNORECASE)
            if match and match.group(1) not in _IGNORED_IPS:
                return match.group(1)

    return "UNKNOWN"


def parse_alert(alert: dict) -> dict:
    """Chuẩn hóa một hit của Wazuh Indexer thành dict phẳng."""
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    mitre = rule.get("mitre") or {}

    def _as_list(v):
        if v is None:
            return []
        return [str(x) for x in v] if isinstance(v, (list, tuple)) else [str(v)]

    return {
        "alert_id":    alert.get("id", "0000"),
        "timestamp":   alert.get("timestamp", ""),
        "rule_id":     str(rule.get("id", "")),
        "rule_desc":   rule.get("description", "Unknown Alert"),
        "rule_level":  int(rule.get("level", 0) or 0),
        "rule_groups": rule.get("groups", []) or [],
        "agent_id":    agent.get("id", ""),
        "agent_name":  agent.get("name", ""),
        "victim_ip":   agent.get("ip") or "UNKNOWN",
        "attacker_ip": extract_attacker_ip(alert),
        "raw_data":    data,
        "full_log":    alert.get("full_log", "") or "",
        "location":    alert.get("location", ""),
        # MITRE do chính Wazuh gắn vào rule (nguồn đáng tin hơn suy đoán)
        "mitre": {
            "ids":        _as_list(mitre.get("id")),
            "tactics":    _as_list(mitre.get("tactic")),
            "techniques": _as_list(mitre.get("technique")),
        },
    }


# ----------------------------------------------------------------------
# Phân loại nhanh
# ----------------------------------------------------------------------
def _alert_text(parsed: dict) -> str:
    return " ".join([parsed["rule_desc"], " ".join(parsed["rule_groups"])]).lower()


def is_brute_force_alert(parsed: dict) -> bool:
    """Alert đăng nhập thất bại — phải ĐẾM chứ không dedup từng cái."""
    if parsed["rule_id"] in COMPOSITE_RULE_IDS:
        return True
    text = _alert_text(parsed)
    return any(marker in text for marker in BRUTE_FORCE_MARKERS)


def is_composite_brute_force(parsed: dict) -> bool:
    """Rule tổng hợp của Wazuh (đã tự gộp nhiều lần thất bại)."""
    if parsed["rule_id"] in COMPOSITE_RULE_IDS:
        return True
    text = _alert_text(parsed)
    return any(marker in text for marker in COMPOSITE_MARKERS)


def is_attack_alert(parsed: dict) -> bool:
    """Lọc nhanh: chỉ giữ alert CÓ THỂ là tấn công."""
    if is_brute_force_alert(parsed):
        if parsed["attacker_ip"] == "UNKNOWN" and parsed["victim_ip"] == "UNKNOWN":
            logger.warning(
                "[PARSE] Brute-force không có IP; vẫn cho qua để tương quan: [%s] %s",
                parsed["rule_id"], parsed["rule_desc"],
            )
        return True

    groups = {g.lower() for g in parsed["rule_groups"]}
    matched = groups & SKIP_GROUPS
    if matched:
        logger.debug("[SKIP] Nhóm tuân thủ/audit %s: %s", matched, parsed["rule_desc"])
        return False

    if parsed["rule_desc"].upper().startswith("CIS"):
        logger.debug("[SKIP] CIS Benchmark: %s", parsed["rule_desc"])
        return False

    has_ip = parsed["attacker_ip"] != "UNKNOWN" or parsed["victim_ip"] != "UNKNOWN"
    if not has_ip:
        logger.info(
            "[SKIP] Không có IP và không phải brute-force: rule [%s] %s | groups=%s",
            parsed["rule_id"], parsed["rule_desc"], parsed["rule_groups"],
        )
        return False
    return True
