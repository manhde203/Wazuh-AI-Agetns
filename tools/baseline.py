"""
tools/baseline.py
-----------------
CrewAI Tool: compare an alert against known-normal behavioral baselines.
Baselines represent expected, recurring, benign events that should NOT
be escalated (scheduled tasks, backup jobs, health checks, etc.).

This is the "baseline comparison" component required by the project spec.
Update BASELINE_RULES to match your environment's normal behavior patterns.
"""

from crewai.tools import tool

# -----------------------------------------------------------------------
# Baseline definitions
# Each entry: rule_id_pattern, description_pattern, notes
# Patterns are simple lowercase substring matches or regex strings.
# -----------------------------------------------------------------------
BASELINE_RULES: list[dict] = [
    {
        "rule_ids":    {"5402", "5403"},
        "desc_keywords": ["cron", "scheduled task", "at command"],
        "note": "Scheduled cron/at jobs — expected system behavior.",
        "fp_confidence": 90,
    },
    {
        "rule_ids":    {"554"},
        "desc_keywords": ["file added to monitored directory"],
        "note": "FIM alert from backup agents writing temp files — expected.",
        "fp_confidence": 85,
    },
    {
        "rule_ids":    {"1002"},
        "desc_keywords": ["unknown problem somewhere in the system"],
        "note": "Generic syslog catch-all — extremely noisy, low signal.",
        "fp_confidence": 80,
    },
    {
        "rule_ids":    {"31101", "31108"},
        "desc_keywords": ["web scan", "scanner", "nessus", "openvas", "nikto"],
        "note": "Authorized vulnerability scanner traffic — whitelist if from known scanner IP.",
        "fp_confidence": 75,
    },
    {
        "rule_ids":    set(),
        "desc_keywords": ["logon type 5", "service account logon", "logon type: 5"],
        "note": "Service account batch logon (Windows type 5) — normal for services.",
        "fp_confidence": 88,
    },
    {
        "rule_ids":    set(),
        "desc_keywords": ["health check", "ping sweep", "icmp echo", "monitoring agent"],
        "note": "Infrastructure health monitoring — expected background traffic.",
        "fp_confidence": 92,
    },
    {
        "rule_ids":    set(),
        "desc_keywords": ["windows update", "wuauserv", "svchost windows update"],
        "note": "Windows Update service activity — expected patch management.",
        "fp_confidence": 95,
    },
    {
        "rule_ids":    set(),
        "desc_keywords": ["antivirus", "windows defender", "malwarebytes", "edr telemetry"],
        "note": "Security tool self-activity — not an external threat.",
        "fp_confidence": 90,
    },
]

# Known internal scanner IPs that generate high-noise alerts
KNOWN_SCANNER_IPS: set[str] = {
    "192.168.1.50",   # Nessus scanner (example — update for your lab)
    "192.168.1.51",   # OpenVAS scanner (example)
}


def evaluate_baseline(rule_id: str, rule_description: str, attacker_ip: str = "") -> dict:
    """
    Hàm thuần (không cần CrewAI): so alert với baseline.
    Trả về dict:
      verdict       : "FP" | "TP"
      fp_confidence : int (0-100)
      matched_by    : mô tả cách khớp ("" nếu không khớp)
      note          : ghi chú của baseline khớp
    Nếu nhiều baseline cùng khớp, chọn baseline có độ tin cậy FP cao nhất.
    """
    desc_lower = (rule_description or "").lower()
    rule_id_str = str(rule_id).strip()

    if attacker_ip and attacker_ip in KNOWN_SCANNER_IPS:
        return {
            "verdict": "FP",
            "fp_confidence": 95,
            "matched_by": f"IP nguồn nằm trong danh sách scanner được phép ({attacker_ip})",
            "note": "Known authorized scanner IP — hoạt động quét được cấp phép.",
        }

    best: dict | None = None
    for baseline in BASELINE_RULES:
        id_match = rule_id_str in baseline["rule_ids"] if baseline["rule_ids"] else False
        matched_kw = [kw for kw in baseline["desc_keywords"] if kw in desc_lower]
        if id_match or matched_kw:
            if best is None or baseline["fp_confidence"] > best["fp_confidence"]:
                best = {
                    "verdict": "FP",
                    "fp_confidence": baseline["fp_confidence"],
                    "matched_by": (
                        f"rule_id={rule_id_str}" if id_match
                        else f"từ khóa mô tả: {', '.join(matched_kw)}"
                    ),
                    "note": baseline["note"],
                }
    if best:
        return best

    return {
        "verdict": "TP",
        "fp_confidence": 0,
        "matched_by": "",
        "note": "Không khớp baseline nào → không phải hành vi bình thường đã biết.",
    }


def format_baseline(result: dict, rule_id: str, rule_description: str) -> str:
    """Định dạng text trả về cho Agent (giữ nguyên dạng cũ)."""
    if result["verdict"] == "FP":
        return (
            f"[BASELINE] rule_id={rule_id} | desc='{rule_description[:60]}'\n"
            f"  Classification : FALSE_POSITIVE\n"
            f"  FP_CONFIDENCE  : {result['fp_confidence']}/100\n"
            f"  Matched By     : {result['matched_by']}\n"
            f"  Baseline Note  : {result['note']}\n"
            f"  Recommendation : SUPPRESS with confidence {result['fp_confidence']}%. "
            f"Do not escalate unless additional context changes the assessment.\n"
            f"  VERDICT        : FP"
        )
    return (
        f"[BASELINE] rule_id={rule_id} | desc='{rule_description[:60]}'\n"
        f"  Classification : POTENTIAL TRUE POSITIVE\n"
        f"  FP_CONFIDENCE  : 0/100 (no baseline match found)\n"
        f"  Matched By     : None\n"
        f"  Recommendation : PROCEED with full threat analysis pipeline.\n"
        f"  VERDICT        : TP"
    )


@tool("Check Baseline")
def check_baseline(rule_id: str, rule_description: str, attacker_ip: str = "") -> str:
    """
    Compare an alert against known-normal behavioral baselines to determine
    if it is likely a false positive or expected system behavior.
    Inputs:
      - rule_id: Wazuh rule ID string (e.g. '5402')
      - rule_description: Wazuh rule description text
      - attacker_ip: source IP from the alert (optional, used to check scanner whitelist)
    Returns: FALSE_POSITIVE or TRUE_POSITIVE classification with confidence score
             and the matched baseline rule (if any).
    Always call this tool as the FIRST step before any threat analysis.
    """
    result = evaluate_baseline(rule_id, rule_description, attacker_ip)
    return format_baseline(result, rule_id, rule_description)
