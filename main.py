"""
main.py — SOC SOAR: Wazuh → lọc → gom nhóm → 4 AI Agent → kết luận → Telegram
================================================================================

Luồng xử lý
  1. Lấy alert mới từ Wazuh Indexer (level ≥ MIN_ALERT_LEVEL, VÀ cả alert đăng
     nhập thất bại level thấp để đếm brute-force).
  2. Lọc nhanh (không LLM) → khử trùng lặp → kiểm tra FP nhanh bằng baseline.
  3. Gom nhóm campaign: brute-force theo cửa sổ trượt; alert thường theo cửa
     sổ gom và được xả bằng bộ hẹn giờ mỗi vòng polling.
  4. Mỗi nhóm chạy pipeline 4 AI Agent (xem pipeline.py), hiển thị từng bước
     trên terminal trong khung viền, ghi file kết luận vào thư mục reports/.
  5. Gửi bản kết luận qua Telegram.

Chạy:  python main.py
Cấu hình: file .env (xem env.example)
"""

import asyncio
import html
import logging
import os
import time

import httpx
from dotenv import load_dotenv

load_dotenv()

import terminal_ui as ui  # noqa: E402
from alert_parser import (  # noqa: E402
    BRUTE_FORCE_QUERY_GROUPS,
    is_attack_alert,
    is_brute_force_alert,
    parse_alert,
)
from grouping import AlertGrouper, Deduper  # noqa: E402
from pipeline import AI_ENABLED, OLLAMA_BASE_URL, OLLAMA_MODEL, run_pipeline  # noqa: E402
from tools.baseline import evaluate_baseline  # noqa: E402
from wazuh_client import WazuhClient  # noqa: E402

ui.init()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("soc_agent")

# ----------------------------------------------------------------------
# Cấu hình
# ----------------------------------------------------------------------
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", 30))
MIN_ALERT_LEVEL = int(os.environ.get("MIN_ALERT_LEVEL", 7))
FETCH_LIMIT = int(os.environ.get("FETCH_LIMIT", 200))
AGENT_TIMEOUT_SEC = int(os.environ.get("AGENT_TIMEOUT_SECONDS", 240))
# 4 agent nối tiếp → mặc định đủ cho cả 4 lần chạm timeout
PIPELINE_TIMEOUT_SEC = int(os.environ.get("PIPELINE_TIMEOUT_SECONDS", AGENT_TIMEOUT_SEC * 4 + 60))
CAMPAIGN_COOLDOWN_SEC = int(os.environ.get("CAMPAIGN_COOLDOWN_SECONDS", 600))
DEDUP_WINDOW_SEC = int(os.environ.get("DEDUP_WINDOW_MINUTES", 10)) * 60
FP_SUPPRESSION_THRESHOLD = int(os.environ.get("FP_SUPPRESSION_THRESHOLD", 80))
GROUP_WINDOW_SEC = int(os.environ.get("ALERT_GROUP_WINDOW_SECONDS", 120))
BRUTE_FORCE_ALERT_THRESHOLD = int(os.environ.get("BRUTE_FORCE_ALERT_THRESHOLD", 20))
BRUTE_FORCE_WINDOW_SEC = int(os.environ.get("BRUTE_FORCE_WINDOW_SECONDS", 60))
# true: rule tổng hợp của Wazuh (đã gộp nhiều lần thất bại) kích hoạt ngay
BRUTE_FORCE_COMPOSITE_TRIGGER = (
    os.environ.get("BRUTE_FORCE_COMPOSITE_TRIGGER", "true").lower() != "false"
)
# Gửi Telegram cho TỪNG alert bị ẩn (FP nhanh). Mặc định tắt vì nay lấy thêm
# alert level thấp nên có thể rất nhiều tin nhắn.
NOTIFY_SUPPRESSED = os.environ.get("NOTIFY_SUPPRESSED", "false").lower() == "true"

_campaign_cooldown: dict[str, float] = {}


# ======================================================================
# Cooldown campaign
# ======================================================================
def _campaign_in_cooldown(key: str) -> bool:
    last = _campaign_cooldown.get(key)
    if last is None:
        return False
    now = time.time()
    if now - last >= CAMPAIGN_COOLDOWN_SEC:
        del _campaign_cooldown[key]
        return False
    logger.info("[CAMPAIGN] Bỏ qua campaign lặp %s; cooldown còn %ds",
                key, int(CAMPAIGN_COOLDOWN_SEC - (now - last)))
    return True


# ======================================================================
# Telegram
# ======================================================================
async def _telegram_post(message: str) -> None:
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url,
                json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
                timeout=10,
            )
            resp.raise_for_status()
    except Exception as e:  # noqa: BLE001
        text = getattr(getattr(e, "response", None), "text", "")
        logger.error("Gửi Telegram thất bại: %s | response=%s", e, text)


def _escape_fit(text: str, limit: int) -> tuple[str, bool]:
    """Escape HTML từng ký tự và dừng trước khi vượt limit, để không cắt giữa
    một entity như '&amp;' (Telegram sẽ từ chối cả tin nhắn)."""
    out: list[str] = []
    used = 0
    for ch in text:
        esc = html.escape(ch)
        if used + len(esc) > limit:
            return "".join(out), True
        out.append(esc)
        used += len(esc)
    return "".join(out), False


async def send_telegram(case_id: str, title: str, body: str, priority: str = "P3") -> None:
    emoji = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "🟢"}.get(priority, "⚪")
    safe_title = html.escape(str(title))
    header = (
        f"🚨 <b>[SOC SOAR] {emoji} {priority} — {safe_title}</b>\n"
        f"{'─' * 40}\n"
        f"📌 <b>Case ID:</b> #INCIDENT_{case_id}\n"
        f"{'─' * 40}\n"
    )
    # Telegram giới hạn toàn bộ message ở 4096 ký tự (không chỉ phần body).
    max_body = 4096 - len(header) - len("\n…[đã rút gọn]")
    safe_body, truncated = _escape_fit(str(body), max_body)
    if truncated:
        safe_body += "\n…[đã rút gọn]"
    await _telegram_post(header + safe_body)
    logger.info("Đã gửi Telegram case %s (%s).", case_id, priority)


async def send_telegram_suppressed(parsed: dict, fp_confidence: int) -> None:
    await _telegram_post(
        f"✅ <b>[SOC SOAR] Alert Suppressed — False Positive</b>\n"
        f"{'─' * 40}\n"
        f"📌 Rule    : [{html.escape(parsed['rule_id'])}] {html.escape(parsed['rule_desc'])}\n"
        f"📌 IP      : {html.escape(parsed['attacker_ip'])} → {html.escape(parsed['victim_ip'])}\n"
        f"📌 FP Conf : {fp_confidence}/100\n"
        f"📌 Status  : Auto-suppressed (baseline match). No action needed."
    )


# ======================================================================
# Kiểm tra FP nhanh (không LLM)
# ======================================================================
def quick_fp_check(parsed: dict) -> tuple[bool, int]:
    r = evaluate_baseline(parsed["rule_id"], parsed["rule_desc"], parsed["attacker_ip"])
    if r["verdict"] == "FP" and r["fp_confidence"] >= FP_SUPPRESSION_THRESHOLD:
        return True, r["fp_confidence"]
    return False, 0


# ======================================================================
# Xử lý một nhóm alert
# ======================================================================
async def process_group(group_key: str, group_alerts: list[dict]) -> None:
    rep = max(group_alerts, key=lambda x: x["rule_level"])
    if _campaign_in_cooldown(group_key):
        return
    logger.info("[PROCESS] Campaign %s | alerts=%d | top_rule=%s | %s → %s",
                group_key, len(group_alerts), rep["rule_desc"],
                rep["attacker_ip"], rep["victim_ip"])
    try:
        concl = await asyncio.wait_for(run_pipeline(group_alerts), timeout=PIPELINE_TIMEOUT_SEC)
    except asyncio.TimeoutError:
        logger.error("Pipeline timeout (%ds) cho campaign %s", PIPELINE_TIMEOUT_SEC, group_key)
        # Đặt cooldown cả khi timeout, tránh chạy lại ~17 phút và gửi [TIMEOUT] lặp lại
        _campaign_cooldown[group_key] = time.time()
        await send_telegram(
            case_id=str(rep["alert_id"])[:12],
            title=f"[TIMEOUT] {rep['rule_desc']}",
            body=(f"⚠️ Pipeline không phản hồi trong {PIPELINE_TIMEOUT_SEC // 60} phút.\n"
                  f"Cần điều tra thủ công.\n\nNguồn: {rep['attacker_ip']}\n"
                  f"Đích: {rep['victim_ip']}\nRule: [{rep['rule_id']}] {rep['rule_desc']}"),
            priority="P2",
        )
        return
    except Exception as e:  # noqa: BLE001
        logger.exception("Lỗi pipeline cho campaign %s: %s", group_key, e)
        return

    _campaign_cooldown[group_key] = time.time()
    if concl["is_attack"]:
        await send_telegram(
            case_id=concl["case_id"],
            title=concl.get("title") or f"[{concl['alert_count']} alerts] {concl['attack_type']}",
            body=concl["report_text"],
            priority=concl["priority"],
        )
    else:
        logger.info("Nhóm %s là False Positive — không gửi Telegram. Báo cáo: %s",
                    group_key, concl["report_path"])


# ======================================================================
# Vòng polling
# ======================================================================
async def fetch_all(wazuh: WazuhClient) -> list[dict]:
    """Lấy hết alert đang chờ (phân trang theo FETCH_LIMIT) để không tồn đọng."""
    collected: list[dict] = []
    for _ in range(50):  # chặn vòng lặp vô hạn
        batch = await wazuh.fetch_new_alerts(
            min_level=MIN_ALERT_LEVEL,
            limit=FETCH_LIMIT,
            extra_groups=BRUTE_FORCE_QUERY_GROUPS,
        )
        collected.extend(batch)
        if len(batch) < FETCH_LIMIT:
            break
    return collected


async def polling_loop() -> None:
    wazuh = WazuhClient()
    deduper = Deduper(DEDUP_WINDOW_SEC)
    grouper = AlertGrouper(
        group_window_sec=GROUP_WINDOW_SEC,
        brute_threshold=BRUTE_FORCE_ALERT_THRESHOLD,
        brute_window_sec=BRUTE_FORCE_WINDOW_SEC,
        composite_trigger=BRUTE_FORCE_COMPOSITE_TRIGGER,
    )

    ui.banner("SOC SOAR · Wazuh + AI Agents · đang chạy")
    ui.box("info", "CẤU HÌNH", [
        ("Wazuh", wazuh.api_url),
        ("Mô hình AI", f"{OLLAMA_MODEL.split('/', 1)[-1]} @ {OLLAMA_BASE_URL}" if AI_ENABLED else "TẮT (AI_ENABLED=false)"),
        ("Polling", f"{POLL_INTERVAL}s · level ≥ {MIN_ALERT_LEVEL} (+ alert đăng nhập thất bại mọi level)"),
        ("Brute-force", f"> {BRUTE_FORCE_ALERT_THRESHOLD} alert/{BRUTE_FORCE_WINDOW_SEC}s hoặc rule tổng hợp "
                        f"({'bật' if BRUTE_FORCE_COMPOSITE_TRIGGER else 'tắt'})"),
        ("Gom nhóm", f"cửa sổ {GROUP_WINDOW_SEC}s · dedup {DEDUP_WINDOW_SEC // 60} phút · "
                     f"cooldown {CAMPAIGN_COOLDOWN_SEC}s"),
        ("Ngưỡng ẩn FP", str(FP_SUPPRESSION_THRESHOLD)),
    ])

    while True:
        try:
            alerts = await fetch_all(wazuh)
            stats = {"fetched": len(alerts), "skipped_filter": 0, "skipped_dedup": 0,
                     "suppressed_fp": 0, "ready": 0}
            ready: list[tuple[str, list[dict]]] = []

            for alert in alerts:
                parsed = parse_alert(alert)

                # Bước 1: lọc nhanh (không LLM)
                if not is_attack_alert(parsed):
                    stats["skipped_filter"] += 1
                    continue

                # Bước 2: khử trùng lặp (brute-force được ĐẾM nên không dedup)
                if not is_brute_force_alert(parsed) and deduper.is_duplicate(parsed):
                    stats["skipped_dedup"] += 1
                    continue

                # Bước 3: FP nhanh bằng baseline (không LLM)
                is_fp, fp_conf = quick_fp_check(parsed)
                if is_fp:
                    stats["suppressed_fp"] += 1
                    logger.info("[FP-FAST] Ẩn (conf=%d%%): %s", fp_conf, parsed["rule_desc"])
                    if NOTIFY_SUPPRESSED:
                        await send_telegram_suppressed(parsed, fp_conf)
                    continue

                # Bước 4: gom nhóm / đếm brute-force
                grouper.add(parsed)

            # Bước 5 [Lỗi 2]: SAU KHI đã nạp hết lô, xả brute-force đã kích hoạt
            # và nhóm đã hết cửa sổ theo ĐỒNG HỒ — kể cả khi vòng này không có alert mới.
            ready.extend(grouper.collect_ready())

            for group_key, group_alerts in ready:
                stats["ready"] += len(group_alerts)
                await process_group(group_key, group_alerts)

            if alerts or ready:
                logger.info(
                    "Vòng xong — lấy=%d bỏ_lọc=%d bỏ_trùng=%d ẩn_FP=%d xử_lý=%d | đang chờ=%s",
                    stats["fetched"], stats["skipped_filter"], stats["skipped_dedup"],
                    stats["suppressed_fp"], stats["ready"], grouper.pending(),
                )
        except Exception as e:  # noqa: BLE001
            logger.exception("Lỗi polling: %s", e)

        await asyncio.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        asyncio.run(polling_loop())
    except KeyboardInterrupt:
        ui.status("Đã dừng theo yêu cầu (Ctrl+C).")
