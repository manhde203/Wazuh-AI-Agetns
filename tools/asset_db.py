"""
tools/asset_db.py
-----------------
CrewAI Tool: tra cứu thông tin tài sản nội bộ theo IP.
Cập nhật dict ASSET_DB cho phù hợp với hạ tầng thực tế của bạn.
"""

from crewai.tools import tool

# ------------------------------------------------------------
# Cơ sở dữ liệu tài sản — cập nhật theo lab của bạn
# ------------------------------------------------------------
ASSET_DB: dict[str, dict] = {
    "192.168.1.10": {
        "hostname":     "WAZUH-SRV",
        "role":         "SIEM / Wazuh Server",
        "tier":         1,
        "os":           "Ubuntu 22.04",
        "owner":        "Security Team",
        "criticality":  "CRITICAL",
        "notes":        "Máy chứa Wazuh. Nếu bị tấn công, toàn bộ khả năng giám sát bị mù.",
    },
    "192.168.1.20": {
        "hostname":     "WEB01",
        "role":         "Web Server (Apache)",
        "tier":         2,
        "os":           "Ubuntu 22.04",
        "owner":        "Dev Team",
        "criticality":  "HIGH",
        "notes":        "Hosting ứng dụng nội bộ. Có thể restart nếu cần.",
    },
    "192.168.1.30": {
        "hostname":     "VICTIM-PC",
        "role":         "End-user Workstation (Lab)",
        "tier":         3,
        "os":           "Ubuntu Server",
        "owner":        "Lab",
        "criticality":  "MEDIUM",
        "notes":        "Máy ảo victim dùng cho thực nghiệm SOC.",
    },
    
}

TIER_LABEL = {1: "Tier 1 — Cốt lõi", 2: "Tier 2 — Quan trọng", 3: "Tier 3 — Thông thường"}


def lookup_asset(ip_address: str) -> dict | None:
    """Trả về thông tin tài sản (kèm nhãn tier, hành động đề xuất) hoặc None."""
    asset = ASSET_DB.get(ip_address)
    if not asset:
        return None
    tier = asset["tier"]
    if tier == 1:
        action = "YÊU CẦU CÔ LẬP NGAY — Tier 1, ảnh hưởng nghiêm trọng đến toàn hệ thống."
    elif tier == 2:
        action = "Giám sát điều tra lại, cân nhắc cô lập nếu xác nhận tấn công thật."
    else:
        action = "Điều tra thêm, ghi nhận sự cố, thông báo chủ sở hữu thiết bị."
    return {
        "ip": ip_address,
        **asset,
        "tier_label": TIER_LABEL.get(tier, f"Tier {tier}"),
        "action": action,
    }


def format_asset(ip_address: str, asset: dict | None) -> str:
    """Định dạng text trả về cho Agent."""
    if not asset:
        return (
            f"[ASSET DB] IP {ip_address} không có trong cơ sở dữ liệu tài sản.\n"
            f"  → Xem xét là thiết bị không rõ nguồn gốc hoặc chưa đăng ký.\n"
            f"  → Kiến nghị: điều tra thủ công."
        )
    return (
        f"[ASSET DB] IP: {ip_address}\n"
        f"  Hostname    : {asset['hostname']}\n"
        f"  Role        : {asset['role']}\n"
        f"  Tier        : {asset['tier_label']}\n"
        f"  ASSET_TIER  : {asset['tier']}\n"
        f"  Hệ điều hành: {asset['os']}\n"
        f"  Chủ sở hữu  : {asset['owner']}\n"
        f"  Mức độ      : {asset['criticality']}\n"
        f"  Ghi chú     : {asset['notes']}\n"
        f"  → Hành động : {asset['action']}"
    )


@tool("Query Asset Database")
def query_asset_db(ip_address: str) -> str:
    """
    Tra cứu thông tin máy chủ / thiết bị theo địa chỉ IP trong cơ sở dữ liệu tài sản nội bộ.
    Truyền vào địa chỉ IP của nạn nhân.
    Trả về tên máy, vai trò, mức độ quan trọng và hành động đề xuất.
    """
    return format_asset(ip_address, lookup_asset(ip_address))
