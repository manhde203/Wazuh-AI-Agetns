"""
tools/threat_intel.py
---------------------
Tra cứu uy tín IP bằng AbuseIPDB (gói miễn phí).

  lookup_ip(ip)          -> dict có cấu trúc (pipeline dùng trực tiếp)
  format_threat_intel(d) -> text cho Agent / webhook
  query_threat_intel     -> CrewAI tool (giữ nguyên tên cũ)

Cải tiến: IP nội bộ (RFC-1918, loopback, link-local) được nhận diện ngay trên
máy, KHÔNG gọi AbuseIPDB (tiết kiệm quota và tránh kết luận sai).
"""

import ipaddress
import os

import httpx
from crewai.tools import tool


def _empty(ip: str, status: str) -> dict:
    return {
        "ip": ip,
        "status": status,        # OK | UNKNOWN_IP | INVALID | PRIVATE | NO_KEY | ERROR
        "risk_tier": None,       # 0-3, None = chưa xác minh được
        "risk_label": "",
        "score": None,
        "reports": None,
        "country": "N/A",
        "isp": "N/A",
        "domain": "N/A",
        "is_tor": False,
        "usage_type": "N/A",
        "is_public": None,
        "is_whitelisted": False,
        "last_reported": "Never",
        "error": "",
    }


def lookup_ip(ip_address: str) -> dict:
    """Tra cứu một IP và trả về dict có cấu trúc (không bao giờ ném lỗi)."""
    ip = (ip_address or "").strip()

    if not ip or ip == "UNKNOWN":
        return _empty(ip or "UNKNOWN", "UNKNOWN_IP")

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return _empty(ip, "INVALID")

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        d = _empty(ip, "PRIVATE")
        d.update(risk_tier=0, risk_label="PRIVATE / RFC-1918", is_public=False)
        return d

    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return _empty(ip, "NO_KEY")

    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
    except Exception as exc:  # noqa: BLE001
        d = _empty(ip, "ERROR")
        d["error"] = f"{type(exc).__name__}: {exc}"
        return d

    score = data.get("abuseConfidenceScore", 0)
    reports = data.get("totalReports", 0)
    is_public = data.get("isPublic", True)
    whitelisted = data.get("isWhitelisted", False)

    if whitelisted:
        label, tier = "WHITELISTED", 0
    elif not is_public:
        label, tier = "PRIVATE / RFC-1918", 0
    elif score >= 75:
        label, tier = "HIGH DANGER", 3
    elif score >= 25:
        label, tier = "SUSPICIOUS", 2
    elif reports > 0:
        label, tier = "LOW RISK (reported but low score)", 1
    else:
        label, tier = "CLEAN / NOT REPORTED", 0

    d = _empty(ip, "OK")
    d.update(
        risk_tier=tier,
        risk_label=label,
        score=score,
        reports=reports,
        country=data.get("countryCode", "N/A"),
        isp=data.get("isp", "N/A"),
        domain=data.get("domain", "N/A"),
        is_tor=bool(data.get("isTor", False)),
        usage_type=data.get("usageType", "N/A"),
        is_public=is_public,
        is_whitelisted=whitelisted,
        last_reported=data.get("lastReportedAt", "Never"),
    )
    return d


def format_threat_intel(d: dict) -> str:
    """Định dạng text trả về cho Agent."""
    ip, status = d["ip"], d["status"]
    if status == "UNKNOWN_IP":
        return (
            "[THREAT INTEL] IP nguồn không xác định; không gọi AbuseIPDB. "
            "RISK_TIER: UNKNOWN. Cần kiểm tra raw log để xác định source IP."
        )
    if status == "INVALID":
        return f"[THREAT INTEL] '{ip}' không phải địa chỉ IP hợp lệ. RISK_TIER: UNKNOWN."
    if status == "PRIVATE":
        return (
            f"[THREAT INTEL] IP: {ip}\n"
            f"  Risk Level        : PRIVATE / RFC-1918 (không tra AbuseIPDB cho IP nội bộ)\n"
            f"  Is Public IP      : False\n"
            f"  RISK_TIER         : 0"
        )
    if status == "NO_KEY":
        return (
            f"[THREAT INTEL] AbuseIPDB API key not configured. "
            f"IP {ip} has not been verified. "
            f"Set ABUSEIPDB_API_KEY in .env to enable live lookups. "
            f"RISK_TIER: UNKNOWN — treat as UNKNOWN RISK and apply cautious escalation."
        )
    if status == "ERROR":
        return (
            f"[THREAT INTEL] ERROR querying IP {ip}: {d['error']}. "
            f"RISK_TIER: UNKNOWN — treat as UNKNOWN RISK and escalate conservatively."
        )
    return (
        f"[THREAT INTEL] IP: {ip}\n"
        f"  Risk Level        : {d['risk_label']} (score: {d['score']}/100, tier: {d['risk_tier']}/3)\n"
        f"  Total Reports     : {d['reports']} (last reported: {d['last_reported']})\n"
        f"  Country           : {d['country']}\n"
        f"  ISP               : {d['isp']}\n"
        f"  Domain            : {d['domain']}\n"
        f"  Is Tor Exit Node  : {'YES — HIGH RISK' if d['is_tor'] else 'No'}\n"
        f"  Is Public IP      : {d['is_public']}\n"
        f"  Is Whitelisted    : {d['is_whitelisted']}\n"
        f"  Usage Type        : {d['usage_type']}\n"
        f"  RISK_TIER         : {d['risk_tier']}"
    )


@tool("Query Threat Intelligence")
def query_threat_intel(ip_address: str) -> str:
    """
    Check the reputation of an IP address via AbuseIPDB.
    Input: IP address string (e.g. '192.168.1.100' or '45.33.32.156').
    Returns: abuse confidence score (0-100), report count, geolocation,
             ISP, Tor status, and a risk classification label.
    Private/internal IPs are recognised locally and are not sent to AbuseIPDB.
    Always call this tool before drawing any conclusion about an attacker IP.
    """
    return format_threat_intel(lookup_ip(ip_address))
