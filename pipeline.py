"""
pipeline.py
-----------
Pipeline 4 AI Agent cho một nhóm alert Wazuh, hiển thị từng bước trên terminal.

  Agent 1  FP Classifier        <- tool: Check Baseline
  Agent 2  L1 SOC Analyst       <- tool: Query Threat Intelligence
  Agent 3  IR Commander         <- tool: Query Asset Database  (+ ma trận ưu tiên)
  Agent 4  Incident Reporter    <- tổng hợp kết quả 3 agent trước
  => KẾT LUẬN: có phải tấn công không / tấn công gì / bằng chứng / biện pháp
     (in ra terminal + lưu file .txt và .json trong thư mục reports/)

Sửa so với bản cũ
  [Lỗi 1] Output của LLM nay ĐƯỢC DÙNG: mỗi agent trả JSON, code kiểm định rồi
          đưa vào báo cáo. Chỉ khi LLM lỗi/trả sai mới dùng kết quả dự phòng
          theo quy tắc (và ghi rõ nguồn trong từng khung).
  [Lỗi 3] Ma trận ưu tiên P1-P4 cài đặt đúng theo prompt (P1 và P4 đều đạt được).
  [Lỗi 4] Báo cáo KHÔNG còn hard-code "BRUTE-FORCE SSH / TRUE POSITIVE / T1110":
          loại tấn công, MITRE, kết luận đều lấy từ alert + kiểm định.

Lưu ý về cách gọi tool: model nhỏ (llama3.2 3B) gọi tool qua function-calling
thiếu ổn định, nên pipeline CHẠY TOOL thay cho agent rồi đưa kết quả vào prompt
của agent đó. Khung hiển thị vẫn ghi rõ agent nào dùng tool nào.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import os
import re
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Tắt telemetry/tracing của CrewAI cho terminal gọn (đặt trước khi import crewai)
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

import prompts  # noqa: E402
import terminal_ui as ui  # noqa: E402
from alert_parser import (  # noqa: E402
    alert_event_time,
    is_brute_force_alert,
    is_composite_brute_force,
    sanitize_text,
)
from tools.asset_db import format_asset, lookup_asset  # noqa: E402
from tools.baseline import evaluate_baseline, format_baseline  # noqa: E402
from tools.threat_intel import format_threat_intel, lookup_ip  # noqa: E402

logger = logging.getLogger("soc_agent.pipeline")

# ----------------------------------------------------------------------
# Cấu hình
# ----------------------------------------------------------------------
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "ollama/llama3.2")
AGENT_TIMEOUT_SEC = int(os.environ.get("AGENT_TIMEOUT_SECONDS", 240))
FP_SUPPRESSION_THRESHOLD = int(os.environ.get("FP_SUPPRESSION_THRESHOLD", 80))
BRUTE_FORCE_ALERT_THRESHOLD = int(os.environ.get("BRUTE_FORCE_ALERT_THRESHOLD", 20))
REPORT_DIR = Path(os.environ.get("REPORT_DIR", str(Path(__file__).parent / "reports")))
AI_ENABLED = os.environ.get("AI_ENABLED", "true").lower() not in ("0", "false", "no")

SEVERITIES = ["Low", "Medium", "High", "Critical"]
CIA_LEVELS = ["Low", "Medium", "High"]
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_PRIVILEGED_USERS = {"root", "admin", "administrator", "sa", "postgres", "oracle"}


def _model_name() -> str:
    return OLLAMA_MODEL.split("/", 1)[-1]


# ======================================================================
# 1) Tổng hợp dữ kiện của nhóm alert
# ======================================================================
def _alert_users(parsed: dict) -> list[str]:
    d = parsed.get("raw_data") or {}
    win = (d.get("win") or {}).get("eventdata") or {}
    audit = d.get("audit") or {}
    vals = [
        d.get("dstuser"), d.get("srcuser"), d.get("user"),
        win.get("targetUserName") if isinstance(win, dict) else None,
        audit.get("acct") if isinstance(audit, dict) else None,
    ]
    return [sanitize_text(v, 40) for v in vals if v]


def summarize_group(alerts: list[dict]) -> dict:
    """Gom dữ kiện khách quan của cả nhóm alert (không dùng LLM)."""
    ordered = sorted(alerts, key=alert_event_time)
    rep = max(alerts, key=lambda a: a["rule_level"])
    t0, t1 = alert_event_time(ordered[0]), alert_event_time(ordered[-1])

    rule_counter = Counter((a["rule_id"], a["rule_desc"]) for a in alerts)
    rules = [f"[{rid}] {desc} x{n}" for (rid, desc), n in rule_counter.most_common(5)]

    user_counter: Counter = Counter()
    for a in alerts:
        user_counter.update(_alert_users(a))
    users = [f"{u} ({n})" for u, n in user_counter.most_common(5)]

    groups: list[str] = []
    mitre = {"ids": [], "tactics": [], "techniques": []}
    for a in alerts:
        for g in a["rule_groups"]:
            if g not in groups:
                groups.append(g)
        for k_src, k_dst in (("ids", "ids"), ("tactics", "tactics"), ("techniques", "techniques")):
            for v in (a.get("mitre") or {}).get(k_src, []):
                if v not in mitre[k_dst]:
                    mitre[k_dst].append(v)

    samples: list[str] = []
    for a in sorted(alerts, key=lambda x: x["rule_level"], reverse=True):
        line = sanitize_text(a.get("full_log", ""), 200)
        if line and line not in samples:
            samples.append(line)
        if len(samples) >= 3:
            break

    return {
        "count": len(alerts),
        "first_ts": ordered[0]["timestamp"],
        "last_ts": ordered[-1]["timestamp"],
        "duration_sec": int(t1 - t0),
        "attacker_ip": rep["attacker_ip"],
        "victim_ip": rep["victim_ip"],
        "agent_name": sanitize_text(rep["agent_name"], 60),
        "rep": {"id": rep["rule_id"], "desc": rep["rule_desc"], "level": rep["rule_level"],
                "alert_id": rep["alert_id"]},
        "max_level": rep["rule_level"],
        "rules": rules,
        "groups": groups,
        "users": users,
        "mitre": mitre,
        "samples": samples,
        "brute_force": any(is_brute_force_alert(a) for a in alerts),
        "composite": any(is_composite_brute_force(a) for a in alerts),
    }


def facts_text(f: dict) -> str:
    """Dữ kiện dạng text đưa vào prompt (phần log được bao trong LOG_DATA)."""
    mitre = f["mitre"]
    mitre_line = (
        f"{', '.join(mitre['ids'])} ({', '.join(mitre['techniques']) or '?'} / "
        f"{', '.join(mitre['tactics']) or '?'})"
        if mitre["ids"] else "none provided by Wazuh"
    )
    lines = [
        f"Alert count        : {f['count']}",
        f"Time span          : {f['first_ts']} -> {f['last_ts']} ({f['duration_sec']} seconds)",
        f"Source (attacker)  : {f['attacker_ip']}",
        f"Victim             : {f['victim_ip']}",
        f"Most severe rule   : [{f['rep']['id']}] {f['rep']['desc']} (Wazuh level {f['rep']['level']})",
        f"Rules in group     : {'; '.join(f['rules'])}",
        f"Rule groups        : {', '.join(f['groups']) or 'none'}",
        f"Brute-force signal : {'yes' if f['brute_force'] else 'no'}"
        f"{' (Wazuh composite rule present)' if f['composite'] else ''}",
        f"MITRE from Wazuh   : {mitre_line}",
        "Untrusted data extracted from logs:",
        "<<<LOG_DATA",
        f"victim_agent_name: {f['agent_name'] or 'unknown'}",
        f"targeted_accounts: {', '.join(f['users']) or 'none extracted'}",
    ]
    for i, s in enumerate(f["samples"], 1):
        lines.append(f"log_sample_{i}: {s}")
    lines.append("LOG_DATA>>>")
    return "\n".join(lines)


# ======================================================================
# 2) Phân loại tấn công (quy tắc) + mức độ + ưu tiên
# ======================================================================
_ATTACK_TABLE = [
    (
        ("brute force", "failed login", "failed password", "authentication failure",
         "authentication_failed", "invalid user", "invalid_login", "non existent user",
         "missed the password", "multiple failed"),
        {"type": "Brute Force", "id": "T1110", "name": "Brute Force",
         "tactic": "Credential Access", "dynamic": "bruteforce"},
    ),
    (
        ("sql injection", "web attack", "xss", "shellshock", "directory traversal",
         "attack on web", "code injection", "command injection"),
        {"type": "Tấn công ứng dụng web", "id": "T1190",
         "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
         "vector": "Gửi request độc hại tới ứng dụng web công khai để khai thác lỗ hổng."},
    ),
    (
        ("port scan", "nmap", "web scan", "scanner", "reconnaissance"),
        {"type": "Quét/Do thám hệ thống", "id": "T1595", "name": "Active Scanning",
         "tactic": "Reconnaissance",
         "vector": "Quét cổng/dịch vụ để thu thập thông tin về mục tiêu."},
    ),
    (
        ("privilege escalation", "sudo"),
        {"type": "Leo thang đặc quyền", "id": "T1548.003",
         "name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation",
         "vector": "Lạm dụng sudo để nâng quyền trên máy đích."},
    ),
    (
        ("rootkit",),
        {"type": "Rootkit", "id": "T1014", "name": "Rootkit", "tactic": "Defense Evasion",
         "vector": "Cài thành phần che giấu hoạt động độc hại trên hệ thống."},
    ),
    (
        ("new user", "user added", "account created", "adduser"),
        {"type": "Tạo tài khoản trái phép", "id": "T1136.001",
         "name": "Create Account: Local Account", "tactic": "Persistence",
         "vector": "Tạo tài khoản cục bộ mới để duy trì truy cập."},
    ),
]


def classify_attack(f: dict) -> dict:
    """
    Gợi ý phân loại theo quy tắc. Ưu tiên MITRE do chính Wazuh gắn vào rule.
    Trả về: attack_type, mitre_id, mitre_name, tactic, vector, mitre_source
    (mitre_source: 'wazuh' | 'rule' | 'none').
    """
    text = " ".join([f["rep"]["desc"], " ".join(f["rules"]), " ".join(f["groups"])]).lower()
    entry = next((e for kws, e in _ATTACK_TABLE if any(k in text for k in kws)), None)

    if entry and entry.get("dynamic") == "bruteforce":
        service = "SSH" if ("sshd" in text or "ssh" in text) else "dịch vụ đăng nhập"
        result = {
            "attack_type": f"Brute Force đăng nhập {service}",
            "vector": f"Thử đăng nhập {service} lặp lại nhiều lần để dò thông tin xác thực.",
        }
    elif entry:
        result = {"attack_type": entry["type"], "vector": entry["vector"]}
    else:
        result = {
            "attack_type": f["rep"]["desc"],
            "vector": "Chưa đủ bằng chứng để mô tả vector tấn công.",
        }

    m = f["mitre"]
    if m["ids"]:
        result.update(
            mitre_id=m["ids"][0],
            mitre_name=(m["techniques"][0] if m["techniques"] else "N/A"),
            tactic=(", ".join(m["tactics"]) if m["tactics"] else "N/A"),
            mitre_source="wazuh",
        )
    elif entry:
        result.update(mitre_id=entry["id"], mitre_name=entry["name"],
                      tactic=entry["tactic"], mitre_source="rule")
    else:
        result.update(mitre_id="N/A", mitre_name="N/A", tactic="N/A", mitre_source="none")
    return result


def severity_by_rule(f: dict, risk_tier: int | None) -> tuple[str, str]:
    """Mức độ tối thiểu theo quy tắc khách quan (AI không được đánh giá thấp hơn)."""
    sev, why = 0, "ít sự kiện, không có dấu hiệu nghiêm trọng"
    if f["count"] >= 5 or f["max_level"] >= 7:
        sev, why = 1, "nhiều sự kiện lặp lại hoặc rule Wazuh từ level 7"
    privileged = any(u.split(" (")[0].lower() in _PRIVILEGED_USERS for u in f["users"])
    high_volume = f["brute_force"] and f["count"] > BRUTE_FORCE_ALERT_THRESHOLD
    if (f["max_level"] >= 10 or (risk_tier or 0) >= 2 or high_volume or privileged
            or f["composite"]):
        sev, why = 2, "rule level ≥ 10 / uy tín xấu / khối lượng lớn / nhắm tài khoản đặc quyền"
    if f["max_level"] >= 13 or ((risk_tier or 0) >= 3 and high_volume):
        sev, why = 3, "rule level ≥ 13 hoặc IP nguồn nguy hiểm kèm khối lượng lớn"
    return SEVERITIES[sev], why


def compute_priority(asset: dict | None, risk_tier: int | None, f: dict) -> tuple[str, list[str]]:
    """
    [Lỗi 3] Ma trận ưu tiên (đúng như mô tả trong prompt cũ):
        P1 : Tier 1 + RISK_TIER >= 2
        P2 : Tier 1 + RISK_TIER < 2   hoặc   Tier 2 + RISK_TIER >= 2
        P3 : Tier 2 + RISK_TIER < 2   hoặc   Tier 3 + RISK_TIER >= 2
        P4 : Tier 3 + RISK_TIER < 2
    RISK_TIER chưa xác minh được (None) → tính là 1 (thận trọng, không phải 0).
    Điều chỉnh: tăng 1 mức nếu rule level >= 12 hoặc khối lượng >= 5 lần ngưỡng.
    """
    reasons: list[str] = []
    if asset:
        tier = min(max(int(asset["tier"]), 1), 3)
        reasons.append(f"Asset Tier {tier} ({asset['hostname']})")
    else:
        tier = 2
        reasons.append("Tài sản chưa đăng ký trong Asset DB → tạm coi là Tier 2 (thận trọng)")

    if risk_tier is None:
        eff = 1
        reasons.append("RISK_TIER chưa xác minh được → tính là 1 (thận trọng)")
    else:
        eff = risk_tier
        reasons.append(f"RISK_TIER = {risk_tier}")
    high = eff >= 2

    if tier == 1:
        level = 1 if high else 2
    elif tier == 2:
        level = 2 if high else 3
    else:
        level = 3 if high else 4
    reasons.append(
        f"Ma trận: Tier {tier} + RISK_TIER {'>= 2' if high else '< 2'} → P{level}"
    )

    mass = f["brute_force"] and f["count"] >= 5 * BRUTE_FORCE_ALERT_THRESHOLD
    if level > 1 and (f["max_level"] >= 12 or mass):
        level -= 1
        reasons.append(
            f"Tăng 1 mức do {'rule level ≥ 12' if f['max_level'] >= 12 else 'khối lượng ≥ 5× ngưỡng'}"
            f" → P{level}"
        )
    return f"P{level}", reasons


# ======================================================================
# 3) Kiểm định đầu ra của AI
# ======================================================================
def _clean(v, n: int = 300) -> str:
    return " ".join(str(v).split())[:n]


def _str(d: dict, key: str, default: str = "", n: int = 300) -> str:
    v = d.get(key)
    if isinstance(v, (str, int, float)) and str(v).strip():
        return _clean(v, n)
    return default


def _list(d: dict, key: str, n: int = 6, m: int = 300) -> list[str]:
    v = d.get(key)
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        return []
    return [_clean(x, m) for x in v[:n] if isinstance(x, (str, int, float)) and str(x).strip()]


def _all_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _all_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _all_strings(v)


def _foreign_ips(data: dict, allowed: set[str]) -> set[str]:
    """IP xuất hiện trong output của AI nhưng KHÔNG có trong bằng chứng = bịa."""
    found: set[str] = set()
    for s in _all_strings(data):
        found.update(_IPV4.findall(s))
    return found - allowed


def extract_json(text: str) -> dict | None:
    """Lấy đối tượng JSON đầu tiên từ output của LLM (chịu được ```json ... ```)."""
    if not text:
        return None
    s = str(text).strip()
    s = re.sub(r"^```(?:json)?\s*|\s*```$", "", s, flags=re.IGNORECASE)
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    start = s.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(s)):
            ch = s[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(s[start:i + 1])
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        break
                    break
        start = s.find("{", start + 1)
    return None


# ----------------------------------------------------------------------
# Kết quả dự phòng (quy tắc) cho từng agent
# ----------------------------------------------------------------------
def fallback_fp(base: dict) -> dict:
    if base["verdict"] == "FP" and base["fp_confidence"] >= FP_SUPPRESSION_THRESHOLD:
        return {
            "verdict": "FP", "confidence": base["fp_confidence"],
            "reasoning": f"Khớp baseline ({base['matched_by']}): {base['note']}",
            "evidence_used": [f"Baseline FP_CONFIDENCE={base['fp_confidence']}", base["note"]],
        }
    return {
        "verdict": "TP", "confidence": None,
        "reasoning": "Không khớp baseline (hoặc độ tin cậy FP dưới ngưỡng) → "
                     "không thể coi là hoạt động bình thường; xử lý như tấn công thật.",
        "evidence_used": [base["note"]],
    }


def fallback_analyst(cls: dict, threat: dict, f: dict, sev: str, sev_why: str) -> dict:
    st = threat["status"]
    if st == "OK":
        ti = (f"AbuseIPDB: score {threat['score']}/100, {threat['reports']} báo cáo, "
              f"quốc gia {threat['country']}, ISP {threat['isp']}, "
              f"Tor: {'có' if threat['is_tor'] else 'không'}.")
    elif st == "PRIVATE":
        ti = "IP nguồn là IP nội bộ — AbuseIPDB không áp dụng; máy nguồn có thể đã bị chiếm quyền hoặc bị lạm dụng."
    elif st == "NO_KEY":
        ti = "Chưa tra cứu được uy tín IP (thiếu ABUSEIPDB_API_KEY)."
    elif st == "ERROR":
        ti = f"Tra cứu uy tín IP thất bại ({threat['error']})."
    else:
        ti = "Không xác định được IP nguồn nên không tra cứu uy tín."
    return {
        "attack_type": cls["attack_type"], "attack_vector": cls["vector"],
        "mitre_id": cls["mitre_id"], "mitre_name": cls["mitre_name"], "tactic": cls["tactic"],
        "severity": sev, "threat_intel_summary": ti,
        "reasoning": f"Mức {sev} theo quy tắc: {sev_why}. Có {f['count']} cảnh báo trong "
                     f"{f['duration_sec']} giây.",
        "evidence_used": [f"{f['count']} cảnh báo", f"Rule nặng nhất [{f['rep']['id']}] "
                          f"level {f['rep']['level']}"],
    }


def _cia_default(asset: dict | None) -> dict:
    if not asset:
        return {"confidentiality": "Medium", "integrity": "Medium", "availability": "Medium"}
    return {
        1: {"confidentiality": "High", "integrity": "High", "availability": "High"},
        2: {"confidentiality": "High", "integrity": "Medium", "availability": "Medium"},
    }.get(int(asset["tier"]), {"confidentiality": "Medium", "integrity": "Low", "availability": "Low"})


def fallback_responder(cls: dict, f: dict, asset: dict | None, priority: str,
                       p_reasons: list[str]) -> dict:
    src, dst = f["attacker_ip"], f["victim_ip"]
    host = asset["hostname"] if asset else dst
    if f["brute_force"]:
        contain = [
            f"Chặn hoặc giới hạn kết nối từ {src} tới {dst} trên firewall (ufw/iptables/fail2ban).",
            "Tạm thời chỉ cho phép dịch vụ đăng nhập từ dải IP quản trị.",
        ]
        eradicate = [
            f"Kiểm tra log xác thực trên {host} xem có đăng nhập THÀNH CÔNG từ {src} không.",
            f"Đặt lại mật khẩu các tài khoản bị nhắm tới: {', '.join(u.split(' (')[0] for u in f['users']) or 'chưa xác định'}.",
        ]
        recover = [
            f"Bật xác thực khóa công khai/MFA và tắt đăng nhập mật khẩu trên {host}.",
            "Xác nhận dịch vụ hoạt động bình thường sau khi thay đổi.",
        ]
        monitor = [f"Theo dõi các lần đăng nhập thất bại từ {src} và IP lạ trong 24 giờ tới."]
    else:
        contain = [f"Cô lập kết nối đáng ngờ từ {src} tới {dst} cho tới khi xác minh xong."]
        eradicate = [f"Phân tích log gốc trên {host} để xác định phạm vi và nguyên nhân."]
        recover = [f"Khôi phục cấu hình/dữ liệu của {host} từ nguồn tin cậy nếu có thay đổi trái phép."]
        monitor = [f"Theo dõi thêm cảnh báo liên quan tới {src} và {dst}."]
    if asset and int(asset["tier"]) == 1:
        contain.append(f"{host} là Tier 1: cô lập NGUỒN trước; cô lập chính {host} cần phê duyệt thay đổi.")
    return {
        "cia_impact": _cia_default(asset),
        "priority_justification": "; ".join(p_reasons)[:300],
        "containment": contain, "eradication": eradicate,
        "recovery": recover, "monitoring": monitor,
    }


def fallback_reporter(concl: dict) -> dict:
    return {
        "title": f"{concl['attack_type']} từ {concl['attacker_ip']} vào {concl['victim_label']}"[:100],
        "executive_summary": (
            f"Ghi nhận {concl['alert_count']} cảnh báo trong {concl['duration_sec']} giây từ "
            f"{concl['attacker_ip']} tới {concl['victim_label']}. Loại tấn công: "
            f"{concl['attack_type']}. Mức độ {concl['severity']}, ưu tiên {concl['priority']}. "
            f"Cần thực hiện các bước ngăn chặn trong kế hoạch xử lý bên dưới."
        ),
        "key_findings": concl["evidence"][:4],
        "next_steps": concl["response"]["containment"][:2],
    }


# ----------------------------------------------------------------------
# Validators: nhận dict của AI -> (kết quả đã kiểm định, source, ghi chú)
# ----------------------------------------------------------------------
def _reject(ai: dict | None, allowed_ips: set[str]) -> str:
    if not ai:
        return "không có JSON hợp lệ"
    bad = _foreign_ips(ai, allowed_ips)
    if bad:
        return f"AI nhắc tới IP không có trong bằng chứng ({', '.join(sorted(bad))})"
    return ""


def validate_fp(ai: dict | None, fb: dict, allowed: set[str]) -> tuple[dict, str, list[str]]:
    why = _reject(ai, allowed)
    if why:
        return fb, "rule", [f"Dùng kết quả quy tắc: {why}"]
    v = str(ai.get("verdict", "")).strip().upper()
    if v not in ("TP", "FP"):
        return fb, "rule", ["Dùng kết quả quy tắc: verdict không phải TP/FP"]
    try:
        conf = max(0, min(100, int(float(ai.get("confidence")))))
    except (TypeError, ValueError):
        conf = None
    notes: list[str] = []
    if v == "FP" and (conf is None or conf < 60):
        notes.append("AI đáp FP nhưng độ tin cậy < 60 → ép về TP (nguyên tắc: nghi ngờ thì TP)")
        v = "TP"
    out = {
        "verdict": v, "confidence": conf,
        "reasoning": _str(ai, "reasoning", fb["reasoning"]),
        "evidence_used": _list(ai, "evidence_used") or fb["evidence_used"],
    }
    return out, "ai", notes


def validate_analyst(ai: dict | None, fb: dict, cls: dict, allowed: set[str],
                     sev_rule: str) -> tuple[dict, str, list[str]]:
    why = _reject(ai, allowed)
    if why:
        return fb, "rule", [f"Dùng kết quả quy tắc: {why}"]
    notes: list[str] = []
    out = dict(fb)
    out["attack_type"] = _str(ai, "attack_type", fb["attack_type"], 120)
    out["attack_vector"] = _str(ai, "attack_vector", fb["attack_vector"])
    out["threat_intel_summary"] = _str(ai, "threat_intel_summary", fb["threat_intel_summary"])
    out["reasoning"] = _str(ai, "reasoning", fb["reasoning"])
    out["evidence_used"] = _list(ai, "evidence_used") or fb["evidence_used"]

    # MITRE: nguồn Wazuh là chuẩn; sau đó tới quy tắc; AI chỉ được bổ sung khi cả hai không có
    ai_id = _str(ai, "mitre_id", "N/A", 20).upper()
    if cls["mitre_source"] in ("wazuh", "rule"):
        out.update(mitre_id=cls["mitre_id"], mitre_name=cls["mitre_name"], tactic=cls["tactic"])
        if ai_id != cls["mitre_id"] and ai_id != "N/A":
            notes.append(f"AI đề xuất {ai_id} khác {cls['mitre_id']} ({cls['mitre_source']}) → giữ {cls['mitre_id']}")
    elif _MITRE_ID.match(ai_id):
        out.update(mitre_id=ai_id, mitre_name=_str(ai, "mitre_name", "N/A", 80),
                   tactic=_str(ai, "tactic", "N/A", 60))
        notes.append(f"MITRE {ai_id} do AI đề xuất, CHƯA được xác minh bởi Wazuh/quy tắc")
    else:
        out.update(mitre_id="N/A", mitre_name="N/A", tactic="N/A")

    # Mức độ: lấy mức CAO HƠN giữa AI và quy tắc (không để AI đánh giá thấp)
    ai_sev = _str(ai, "severity", "", 20).capitalize()
    if ai_sev in SEVERITIES:
        if SEVERITIES.index(ai_sev) < SEVERITIES.index(sev_rule):
            notes.append(f"AI chọn {ai_sev} < mức tối thiểu theo quy tắc {sev_rule} → dùng {sev_rule}")
            out["severity"] = sev_rule
        else:
            out["severity"] = ai_sev
    else:
        notes.append("severity của AI không hợp lệ → dùng mức theo quy tắc")
        out["severity"] = sev_rule
    return out, "ai", notes


def validate_responder(ai: dict | None, fb: dict, allowed: set[str]) -> tuple[dict, str, list[str]]:
    why = _reject(ai, allowed)
    if why:
        return fb, "rule", [f"Dùng kết quả quy tắc: {why}"]
    notes: list[str] = []
    cia_in = ai.get("cia_impact") if isinstance(ai.get("cia_impact"), dict) else {}
    cia = {}
    for k in ("confidentiality", "integrity", "availability"):
        val = _str(cia_in, k, "", 10).capitalize()
        cia[k] = val if val in CIA_LEVELS else fb["cia_impact"][k]
    out = {"cia_impact": cia,
           "priority_justification": _str(ai, "priority_justification", fb["priority_justification"])}
    for key in ("containment", "eradication", "recovery", "monitoring"):
        items = _list(ai, key, 5, 300)
        if not items:
            notes.append(f"AI không đưa '{key}' → dùng bước theo quy tắc")
        out[key] = items or fb[key]
    return out, "ai", notes


def validate_reporter(ai: dict | None, fb: dict, allowed: set[str]) -> tuple[dict, str, list[str]]:
    why = _reject(ai, allowed)
    if why:
        return fb, "rule", [f"Dùng kết quả quy tắc: {why}"]
    summary = _str(ai, "executive_summary", "", 900)
    if len(summary) < 40:
        return fb, "rule", ["Dùng kết quả quy tắc: executive_summary quá ngắn/trống"]
    out = {
        "title": _str(ai, "title", fb["title"], 100),
        "executive_summary": summary,
        "key_findings": _list(ai, "key_findings", 5) or fb["key_findings"],
        "next_steps": _list(ai, "next_steps", 3) or fb["next_steps"],
    }
    return out, "ai", []


# ======================================================================
# 4) Gọi LLM qua CrewAI (mỗi agent một Crew một Task)
# ======================================================================
_llm_cache = None


def _get_llm():
    global _llm_cache
    if _llm_cache is None:
        from crewai import LLM
        _llm_cache = LLM(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.1)
    return _llm_cache


def _kickoff_sync(agent_key: str, description: str, expected_output: str) -> str:
    """Chạy một agent CrewAI (đồng bộ, dùng trong thread)."""
    from crewai import Agent, Crew, Task

    spec = prompts.AGENTS[agent_key]
    agent = Agent(
        role=spec["role"], goal=spec["goal"], backstory=spec["backstory"],
        llm=_get_llm(), tools=[], verbose=False, allow_delegation=False,
    )
    task = Task(description=description, expected_output=expected_output, agent=agent)
    crew = Crew(agents=[agent], tasks=[task], verbose=False)

    # CrewAI tự in panel; chặn lại để terminal chỉ có khung của hệ thống.
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        out = crew.kickoff()
    return getattr(out, "raw", None) or str(out)


def _ai_status(action: str, n: int) -> None:
    """Dòng trạng thái: nói rõ AI hay quy tắc đang xử lý."""
    if AI_ENABLED:
        ui.status(f"Agent {n} đang {action} ({_model_name()})...")
    else:
        ui.status(f"Agent {n}: AI tắt → dùng quy tắc dự phòng.")


async def _call_ai(agent_key: str, task: tuple[str, str]) -> tuple[dict | None, str, float]:
    """Trả về (json_hoặc_None, lỗi, giây)."""
    if not AI_ENABLED:
        return None, "AI đang tắt (AI_ENABLED=false)", 0.0
    t0 = time.time()
    try:
        raw = await asyncio.wait_for(
            asyncio.to_thread(_kickoff_sync, agent_key, task[0], task[1]),
            timeout=AGENT_TIMEOUT_SEC,
        )
    except asyncio.TimeoutError:
        return None, f"quá thời gian {AGENT_TIMEOUT_SEC}s", time.time() - t0
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}", time.time() - t0
    data = extract_json(raw)
    if data is None:
        logger.warning("[%s] LLM không trả JSON hợp lệ. Output đầu: %r", agent_key, str(raw)[:200])
        return None, "LLM không trả về JSON hợp lệ", time.time() - t0
    return data, "", time.time() - t0


def _source_line(source: str, dt: float, err: str, notes: list[str]) -> list:
    if source == "ai":
        line = f"AI ({_model_name()}) · {dt:.1f}s · đã kiểm định"
    else:
        line = "QUY TẮC DỰ PHÒNG — " + (err or (notes[0] if notes else "AI không dùng được"))
    rows = [("Nguồn kết quả", line)]
    extra = [n for n in notes if not n.startswith("Dùng kết quả quy tắc")]
    if extra:
        rows.append(("Kiểm định", extra))
    return rows


# ======================================================================
# 5) Báo cáo kết luận
# ======================================================================
def _threat_evidence(threat: dict) -> str:
    st = threat["status"]
    if st == "OK":
        return (f"Uy tín IP nguồn (AbuseIPDB): score {threat['score']}/100, {threat['reports']} "
                f"báo cáo, {threat['country']}, ISP {threat['isp']}, RISK_TIER {threat['risk_tier']}")
    if st == "PRIVATE":
        return "IP nguồn là IP nội bộ (RFC-1918) → không tra AbuseIPDB; cần kiểm tra chính máy nguồn"
    if st == "NO_KEY":
        return "Chưa tra cứu uy tín IP nguồn (thiếu ABUSEIPDB_API_KEY)"
    if st == "ERROR":
        return f"Tra cứu uy tín IP thất bại: {threat['error']}"
    return "Không xác định được IP nguồn"


def build_evidence(f: dict, base: dict, threat: dict, asset: dict | None, cls: dict) -> list[str]:
    ev = [
        f"{f['count']} cảnh báo trong {f['duration_sec']} giây ({f['first_ts']} → {f['last_ts']})",
        f"Rule nặng nhất: [{f['rep']['id']}] {f['rep']['desc']} (level {f['rep']['level']})",
    ]
    if len(f["rules"]) > 1:
        ev.append("Các rule trong nhóm: " + "; ".join(f["rules"]))
    if f["users"]:
        ev.append("Tài khoản bị nhắm tới: " + ", ".join(f["users"]))
    ev.append(f"Nguồn {f['attacker_ip']} → đích {f['victim_ip']}")
    ev.append(_threat_evidence(threat))
    if asset:
        ev.append(f"Tài sản bị ảnh hưởng: {asset['hostname']} — {asset['role']} "
                  f"({asset['tier_label']}, {asset['criticality']})")
    else:
        ev.append(f"Tài sản {f['victim_ip']} chưa đăng ký trong cơ sở dữ liệu tài sản")
    ev.append("Baseline: " + base["note"])
    if cls["mitre_source"] == "wazuh":
        ev.append(f"MITRE ATT&CK do Wazuh gắn cho rule: {cls['mitre_id']} ({cls['tactic']})")
    for i, s in enumerate(f["samples"][:2], 1):
        ev.append(f"Log mẫu {i}: {s}")
    return ev


def render_report(c: dict) -> str:
    """Báo cáo kết luận dạng text thuần (lưu file + gửi Telegram)."""
    line = "=" * 78
    out = [line, f"KẾT LUẬN SỰ CỐ  #{c['case_id']}", line,
           f"Thời điểm lập báo cáo : {c['generated_at']}",
           f"Nguồn → Đích          : {c['attacker_ip']} → {c['victim_label']}", ""]

    out.append("1) ĐÂY CÓ PHẢI LÀ TẤN CÔNG KHÔNG?")
    if c["is_attack"]:
        conf = f", độ tin cậy phân loại {c['fp_confidence']}/100" if c["fp_confidence"] is not None else ""
        out.append(f"   CÓ — TRUE POSITIVE{conf}.")
    else:
        out.append("   KHÔNG — FALSE POSITIVE (hoạt động bình thường, đã tự động ẩn).")
    out.append(f"   Lý do: {c['verdict_reason']}")
    out.append("")

    if c["is_attack"]:
        out += ["2) LOẠI TẤN CÔNG",
                f"   {c['attack_type']}",
                f"   Vector   : {c['attack_vector']}",
                f"   MITRE    : {c['mitre_label']}",
                f"   Mức độ   : {c['severity']}   |   Ưu tiên: {c['priority']}",
                f"   Uy tín IP: {c['threat_summary']}", ""]
    else:
        out += ["2) LOẠI TẤN CÔNG", "   Không có (đã loại trừ là dương tính giả).", ""]

    out.append("3) BẰNG CHỨNG")
    out += [f"   - {e}" for e in c["evidence"]]
    out.append("")

    out.append("4) BIỆN PHÁP XỬ LÝ")
    if c["is_attack"]:
        r = c["response"]
        for title, key in (("Ngăn chặn (Containment)", "containment"),
                           ("Loại bỏ (Eradication)", "eradication"),
                           ("Khôi phục (Recovery)", "recovery"),
                           ("Giám sát sau sự cố", "monitoring")):
            out.append(f"   {title}:")
            out += [f"     - {s}" for s in r.get(key, [])]
        out.append(f"   Tác động CIA: C={c['cia']['confidentiality']}, "
                   f"I={c['cia']['integrity']}, A={c['cia']['availability']}")
    else:
        out.append("   Không cần xử lý. Alert được ghi nhận để kiểm toán.")
    out.append("")

    if c.get("summary"):
        out += ["5) TÓM TẮT ĐIỀU HÀNH", f"   {c['summary']}", ""]
    if c.get("priority_reasons"):
        out.append("CÁCH TÍNH ƯU TIÊN: " + " | ".join(c["priority_reasons"]))
    out.append("NGUỒN KẾT LUẬN CỦA TỪNG AGENT: " + ", ".join(f"{k}={v}" for k, v in c["sources"].items()))
    out.append(line)
    return "\n".join(out)


def write_report(c: dict) -> tuple[Path, Path]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "", str(c["case_id"]))[:16] or "case"
    base = REPORT_DIR / f"incident_{stamp}_{safe_id}"
    txt, js = base.with_suffix(".txt"), base.with_suffix(".json")
    txt.write_text(c["report_text"], encoding="utf-8")
    payload = {k: v for k, v in c.items() if k != "report_text"}
    js.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return txt, js


# ======================================================================
# 6) Pipeline chính
# ======================================================================
async def run_pipeline(alerts: list[dict]) -> dict:
    """Chạy 4 agent cho một nhóm alert. Trả về dict kết luận (có report_text)."""
    f = summarize_group(alerts)
    facts = facts_text(f)
    victim_label = f["victim_ip"] + (f" ({f['agent_name']})" if f["agent_name"] else "")
    sources: dict[str, str] = {}
    t_start = time.time()

    ui.banner(f"SOC SOAR · PHÂN TÍCH CHIẾN DỊCH · {f['count']} cảnh báo · "
              f"{f['attacker_ip']} → {f['victim_ip']}")
    ui.box("info", "TỔNG QUAN NHÓM CẢNH BÁO", [
        ("Rule nặng nhất", f"[{f['rep']['id']}] {f['rep']['desc']} (level {f['rep']['level']})"),
        ("Khoảng thời gian", f"{f['first_ts']} → {f['last_ts']} ({f['duration_sec']}s)"),
        ("Mô hình AI", f"{_model_name()} @ {OLLAMA_BASE_URL}" if AI_ENABLED else "TẮT — chỉ dùng quy tắc"),
        ("Quy trình", "Agent 1 → Agent 2 → Agent 3 → Agent 4 → Kết luận"),
    ])

    # ---------------------------------------------------------------- Agent 1
    ui.arrow()
    ui.box("agent", "AI AGENT 1/4 · SOC False Positive Classifier", [
        ("Chức năng", "Phân loại nhóm cảnh báo là tấn công thật (TP) hay dương tính giả (FP) "
                      "để tránh làm phiền analyst mà không bỏ sót tấn công."),
        ("Công cụ sẽ gọi", "Check Baseline"),
        ("Nguyên tắc", f"Chỉ ẩn alert khi baseline VÀ AI cùng kết luận FP "
                       f"(baseline ≥ {FP_SUPPRESSION_THRESHOLD}); nghi ngờ thì coi là TP."),
    ])
    ui.arrow("Agent 1 gọi tool")
    base = evaluate_baseline(f["rep"]["id"], f["rep"]["desc"], f["attacker_ip"])
    baseline_text = format_baseline(base, f["rep"]["id"], f["rep"]["desc"])
    ui.box("tool", "TOOL · Check Baseline", [
        ("Đầu vào", f"rule_id={f['rep']['id']} · IP nguồn={f['attacker_ip']}"),
        ("Mô tả rule", f["rep"]["desc"]),
        ui.SEP,
        ("Phân loại", "FALSE POSITIVE" if base["verdict"] == "FP" else "TRUE POSITIVE (không khớp baseline)"),
        ("FP_CONFIDENCE", f"{base['fp_confidence']}/100"),
        ("Khớp theo", base["matched_by"] or "không khớp"),
        ("Ghi chú baseline", base["note"]),
    ])
    ui.arrow("trả bằng chứng cho Agent 1")

    allowed_ips = set(_IPV4.findall(facts)) | {f["attacker_ip"], f["victim_ip"]}
    _ai_status("phân tích", 1)
    ai, err, dt = await _call_ai("fp", prompts.fp_task(facts, baseline_text, FP_SUPPRESSION_THRESHOLD))
    fp, src, notes = validate_fp(ai, fallback_fp(base), allowed_ips)
    sources["agent1_fp"] = src

    # Guardrail: chỉ ẩn khi baseline VÀ agent cùng nói FP
    suppress = (fp["verdict"] == "FP" and base["verdict"] == "FP"
                and base["fp_confidence"] >= FP_SUPPRESSION_THRESHOLD)
    if fp["verdict"] == "FP" and not suppress:
        notes.append("Guardrail: AI đáp FP nhưng baseline không đủ ngưỡng → KHÔNG ẩn, xử lý như TP")
        fp["verdict"] = "TP"
    ui.box("result", "AI AGENT 1/4 · KẾT QUẢ", [
        ("Kết luận", ("FALSE POSITIVE → ẨN ALERT" if suppress else "TRUE POSITIVE → TIẾP TỤC PHÂN TÍCH")),
        ("Độ tin cậy", f"{fp['confidence']}/100" if fp["confidence"] is not None else "không áp dụng (quy tắc)"),
        ("Dựa vào", fp["evidence_used"]),
        ("Lý do", fp["reasoning"]),
        *_source_line(src, dt, err, notes),
    ])

    if suppress:
        ui.arrow()
        ui.status("Agent 2, 3, 4 được bỏ qua vì alert là dương tính giả.")
        concl = {
            "case_id": str(f["rep"]["alert_id"])[:12], "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "is_attack": False, "verdict": "FALSE POSITIVE", "fp_confidence": fp["confidence"],
            "verdict_reason": fp["reasoning"], "attacker_ip": f["attacker_ip"],
            "victim_ip": f["victim_ip"], "victim_label": victim_label, "alert_count": f["count"],
            "duration_sec": f["duration_sec"], "attack_type": "", "attack_vector": "",
            "mitre_label": "", "severity": "", "priority": "P4", "priority_reasons": [],
            "threat_summary": "", "evidence": [f"{f['count']} cảnh báo rule [{f['rep']['id']}] {f['rep']['desc']}",
                                               f"Baseline: {base['note']} ({base['matched_by']})"],
            "response": {}, "cia": {}, "summary": "", "sources": sources,
        }
        return _finish(concl, t_start)

    # ---------------------------------------------------------------- Agent 2
    ui.arrow()
    ui.box("agent", "AI AGENT 2/4 · L1 SOC Analyst", [
        ("Chức năng", "Xác định loại tấn công, vector, ánh xạ MITRE ATT&CK và mức độ nghiêm "
                      "trọng dựa trên dữ kiện alert và uy tín IP nguồn."),
        ("Công cụ sẽ gọi", "Query Threat Intelligence"),
        ("Đầu vào", f"IP nguồn {f['attacker_ip']} · {f['count']} cảnh báo"),
    ])
    ui.arrow("Agent 2 gọi tool")
    threat = await asyncio.to_thread(lookup_ip, f["attacker_ip"])
    threat_text = format_threat_intel(threat)
    t_rows = [("Đầu vào", f"ip_address={f['attacker_ip']}"), ui.SEP, ("Trạng thái", threat["status"])]
    if threat["status"] == "OK":
        t_rows += [("Mức rủi ro", f"{threat['risk_label']} (score {threat['score']}/100)"),
                   ("Số báo cáo", f"{threat['reports']} (gần nhất: {threat['last_reported']})"),
                   ("Quốc gia / ISP", f"{threat['country']} / {threat['isp']}"),
                   ("Tor exit node", "CÓ" if threat["is_tor"] else "Không"),
                   ("RISK_TIER", str(threat["risk_tier"]))]
    else:
        t_rows += [("Diễn giải", _threat_evidence(threat)),
                   ("RISK_TIER", str(threat["risk_tier"]) if threat["risk_tier"] is not None else "chưa xác minh")]
    ui.box("tool", "TOOL · Query Threat Intelligence", t_rows)
    ui.arrow("trả bằng chứng cho Agent 2")

    cls = classify_attack(f)
    sev_rule, sev_why = severity_by_rule(f, threat["risk_tier"])
    hint = (f"Suggested attack type : {cls['attack_type']}\n"
            f"Suggested MITRE        : {cls['mitre_id']} {cls['mitre_name']} / {cls['tactic']} "
            f"(source: {cls['mitre_source']})\n"
            f"Minimum severity (rule): {sev_rule} — {sev_why}")
    allowed_ips |= set(_IPV4.findall(threat_text))
    _ai_status("phân tích", 2)
    ai, err, dt = await _call_ai("analyst", prompts.analyst_task(facts, threat_text, hint))
    an, src, notes = validate_analyst(ai, fallback_analyst(cls, threat, f, sev_rule, sev_why),
                                      cls, allowed_ips, sev_rule)
    sources["agent2_analyst"] = src
    mitre_label = (f"{an['mitre_id']} — {an['mitre_name']} ({an['tactic']})"
                   if an["mitre_id"] != "N/A" else "Chưa đủ bằng chứng để ánh xạ MITRE ATT&CK")
    ui.box("result", "AI AGENT 2/4 · KẾT QUẢ", [
        ("Loại tấn công", an["attack_type"]),
        ("Vector", an["attack_vector"]),
        ("MITRE ATT&CK", mitre_label),
        ("Mức độ", f"{an['severity']} (tối thiểu theo quy tắc: {sev_rule})"),
        ("Uy tín IP", an["threat_intel_summary"]),
        ("Dựa vào", an["evidence_used"]),
        ("Lý do", an["reasoning"]),
        *_source_line(src, dt, err, notes),
    ])

    # ---------------------------------------------------------------- Agent 3
    ui.arrow()
    ui.box("agent", "AI AGENT 3/4 · Incident Response Commander", [
        ("Chức năng", "Đánh giá tác động lên tài sản bị tấn công (CIA) và lập kế hoạch ứng phó "
                      "theo NIST SP 800-61 (Containment / Eradication / Recovery)."),
        ("Công cụ sẽ gọi", "Query Asset Database"),
        ("Đầu vào", f"IP nạn nhân {f['victim_ip']} · phân tích của Agent 2"),
    ])
    ui.arrow("Agent 3 gọi tool")
    asset = lookup_asset(f["victim_ip"])
    asset_text = format_asset(f["victim_ip"], asset)
    if asset:
        a_rows = [("Đầu vào", f"ip_address={f['victim_ip']}"), ui.SEP,
                  ("Hostname", asset["hostname"]), ("Vai trò", asset["role"]),
                  ("Tier", f"{asset['tier_label']} (ASSET_TIER={asset['tier']})"),
                  ("Mức độ quan trọng", asset["criticality"]), ("Chủ sở hữu", asset["owner"]),
                  ("Ghi chú", asset["notes"]), ("Hành động theo tier", asset["action"])]
    else:
        a_rows = [("Đầu vào", f"ip_address={f['victim_ip']}"), ui.SEP,
                  ("Kết quả", "KHÔNG có trong cơ sở dữ liệu tài sản"),
                  ("Diễn giải", "Thiết bị chưa đăng ký hoặc không rõ nguồn gốc → điều tra thủ công.")]
    ui.box("tool", "TOOL · Query Asset Database", a_rows)
    ui.arrow("trả bằng chứng cho Agent 3")

    priority, p_reasons = compute_priority(asset, threat["risk_tier"], f)
    prio_text = f"{priority}  (" + " | ".join(p_reasons) + ")"
    analysis_text = (f"attack_type: {an['attack_type']}\nattack_vector: {an['attack_vector']}\n"
                     f"mitre: {an['mitre_id']} {an['mitre_name']} / {an['tactic']}\n"
                     f"severity: {an['severity']}\nthreat_intel: {an['threat_intel_summary']}")
    allowed_ips |= set(_IPV4.findall(asset_text))
    _ai_status("lập kế hoạch ứng phó", 3)
    ai, err, dt = await _call_ai("responder", prompts.responder_task(facts, analysis_text, asset_text, prio_text))
    rs, src, notes = validate_responder(ai, fallback_responder(cls, f, asset, priority, p_reasons), allowed_ips)
    sources["agent3_responder"] = src
    ui.box("result", "AI AGENT 3/4 · KẾT QUẢ", [
        ("Mức ưu tiên", f"{priority} (do ma trận quy tắc tính, AI không được đổi)"),
        ("Cách tính", p_reasons),
        ("Tác động CIA", f"C={rs['cia_impact']['confidentiality']} · I={rs['cia_impact']['integrity']} · "
                         f"A={rs['cia_impact']['availability']}"),
        ("Giải thích", rs["priority_justification"]),
        ui.SEP,
        ("Ngăn chặn", rs["containment"]), ("Loại bỏ", rs["eradication"]),
        ("Khôi phục", rs["recovery"]), ("Giám sát", rs["monitoring"]),
        *_source_line(src, dt, err, notes),
    ])

    # ---------------------------------------------------------------- Agent 4
    ui.arrow()
    ui.box("agent", "AI AGENT 4/4 · SOC Incident Reporter", [
        ("Chức năng", "Tổng hợp kết quả của Agent 1-3 thành tóm tắt điều hành ngắn gọn, "
                      "chính xác cho quản trị viên."),
        ("Công cụ sẽ gọi", "Không dùng tool — tổng hợp dữ liệu đã kiểm định của 3 agent trước"),
    ])
    concl = {
        "case_id": str(f["rep"]["alert_id"])[:12], "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "is_attack": True, "verdict": "TRUE POSITIVE", "fp_confidence": fp["confidence"],
        "verdict_reason": fp["reasoning"], "attacker_ip": f["attacker_ip"], "victim_ip": f["victim_ip"],
        "victim_label": victim_label, "alert_count": f["count"], "duration_sec": f["duration_sec"],
        "attack_type": an["attack_type"], "attack_vector": an["attack_vector"],
        "mitre_label": mitre_label, "mitre": {"id": an["mitre_id"], "name": an["mitre_name"], "tactic": an["tactic"]},
        "severity": an["severity"], "priority": priority, "priority_reasons": p_reasons,
        "threat_summary": an["threat_intel_summary"],
        "evidence": build_evidence(f, base, threat, asset, cls),
        "response": {k: rs[k] for k in ("containment", "eradication", "recovery", "monitoring")},
        "cia": rs["cia_impact"], "summary": "", "sources": sources,
    }
    case_text = "\n".join([
        f"verdict: TRUE POSITIVE (this is an attack)", f"attack_type: {concl['attack_type']}",
        f"mitre: {concl['mitre_label']}", f"severity: {concl['severity']}", f"priority: {priority}",
        f"source_ip: {f['attacker_ip']}", f"victim: {victim_label}",
        f"alert_count: {f['count']} in {f['duration_sec']} seconds",
        "evidence:", *[f"- {e}" for e in concl["evidence"] if not e.startswith("Log mẫu")],
        "containment_plan:", *[f"- {s}" for s in rs["containment"]],
    ])
    ui.arrow("Agent 4 tổng hợp")
    _ai_status("viết tóm tắt", 4)
    ai, err, dt = await _call_ai("reporter", prompts.reporter_task(case_text))
    rp, src, notes = validate_reporter(ai, fallback_reporter(concl), allowed_ips)
    sources["agent4_reporter"] = src
    concl["summary"] = rp["executive_summary"]
    concl["title"] = rp["title"]
    ui.box("result", "AI AGENT 4/4 · KẾT QUẢ", [
        ("Tiêu đề", rp["title"]),
        ("Tóm tắt điều hành", rp["executive_summary"]),
        ("Phát hiện chính", rp["key_findings"]),
        ("Việc cần làm ngay", rp["next_steps"]),
        *_source_line(src, dt, err, notes),
    ])
    return _finish(concl, t_start)


def _finish(concl: dict, t_start: float) -> dict:
    """Dựng báo cáo, ghi file, in khung KẾT LUẬN cuối cùng."""
    concl["report_text"] = render_report(concl)
    txt, js = write_report(concl)
    concl["report_path"], concl["json_path"] = str(txt), str(js)

    ui.arrow()
    if concl["is_attack"]:
        ui.box("attack", f"KẾT LUẬN CUỐI CÙNG · ĐÂY LÀ TẤN CÔNG · {concl['priority']} · {concl['severity']}", [
            ("Có phải tấn công?", "CÓ — TRUE POSITIVE"),
            ("Loại tấn công", concl["attack_type"]),
            ("MITRE ATT&CK", concl["mitre_label"]),
            ("Nguồn → Đích", f"{concl['attacker_ip']} → {concl['victim_label']}"),
            ui.SEP,
            ("Bằng chứng", concl["evidence"]),
            ui.SEP,
            ("Ngăn chặn", concl["response"]["containment"]),
            ("Loại bỏ", concl["response"]["eradication"]),
            ("Khôi phục", concl["response"]["recovery"]),
            ui.SEP,
            ("File kết luận", [concl["report_path"], concl["json_path"]]),
            ("Thời gian xử lý", f"{time.time() - t_start:.1f}s"),
        ])
    else:
        ui.box("clean", "KẾT LUẬN CUỐI CÙNG · KHÔNG PHẢI TẤN CÔNG (False Positive)", [
            ("Có phải tấn công?", "KHÔNG — FALSE POSITIVE"),
            ("Lý do", concl["verdict_reason"]),
            ("Bằng chứng", concl["evidence"]),
            ("File kết luận", [concl["report_path"], concl["json_path"]]),
            ("Thời gian xử lý", f"{time.time() - t_start:.1f}s"),
        ])
    logger.info("Pipeline xong: %d alert, is_attack=%s, priority=%s, file=%s",
                concl["alert_count"], concl["is_attack"], concl["priority"], concl["report_path"])
    return concl
