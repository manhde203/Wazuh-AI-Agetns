"""
grouping.py
-----------
Khử trùng lặp, gom nhóm campaign và đếm brute-force.

Sửa so với bản cũ
  [Lỗi 2] Nhóm alert thường chỉ được xả khi có alert MỚI cùng nguồn đến sau
          khi hết cửa sổ → alert đơn lẻ nằm trong cache mãi mãi. Nay có
          collect_ready() được gọi MỖI vòng polling (theo đồng hồ), nên nhóm
          luôn được xả khi hết cửa sổ dù không có alert mới.
  [Lỗi 6] Brute-force dùng cửa sổ TRƯỢT theo thời gian sự kiện, và rule tổng
          hợp của Wazuh (đã gộp nhiều lần thất bại) kích hoạt ngay, không bắt
          phải có > N alert cùng loại trong 60 giây.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Callable

from alert_parser import (
    alert_event_time,
    is_brute_force_alert,
    is_composite_brute_force,
)

logger = logging.getLogger("soc_agent.grouping")

Group = tuple[str, list[dict]]


class Deduper:
    """Bỏ alert trùng (cùng rule + IP nguồn + IP đích) trong một khoảng thời gian."""

    def __init__(self, window_sec: int, clock: Callable[[], float] = time.time):
        self.window = window_sec
        self.clock = clock
        self._seen: dict[str, float] = {}

    def is_duplicate(self, parsed: dict) -> bool:
        key = f"{parsed['rule_id']}|{parsed['attacker_ip']}|{parsed['victim_ip']}"
        now = self.clock()
        for k in [k for k, t in self._seen.items() if now - t > self.window]:
            del self._seen[k]
        if key in self._seen:
            logger.info(
                "[DEDUP] Bỏ alert trùng (%ds trước): %s",
                int(now - self._seen[key]), parsed["rule_desc"],
            )
            return True
        self._seen[key] = now
        return False


class AlertGrouper:
    def __init__(
        self,
        group_window_sec: int = 120,
        brute_threshold: int = 20,
        brute_window_sec: int = 60,
        composite_trigger: bool = True,
        clock: Callable[[], float] = time.time,
    ):
        self.group_window = group_window_sec
        self.bf_threshold = brute_threshold
        self.bf_window = brute_window_sec
        self.composite_trigger = composite_trigger
        self.clock = clock

        # nhóm alert thường: key -> {"first": wall_ts, "alerts": [...]}
        self._groups: dict[str, dict] = {}
        # brute-force: key -> list[(event_ts, parsed)] + lần cập nhật cuối (wall)
        self._bf: dict[str, list[tuple[float, dict]]] = defaultdict(list)
        self._bf_touched: dict[str, float] = {}
        # key đã đạt điều kiện kích hoạt; chỉ xả ở collect_ready() để nhóm chứa
        # ĐỦ alert của cả lô (kể cả rule tổng hợp đến sau alert thứ 21).
        self._bf_triggered: dict[str, str] = {}

    # ------------------------------------------------------------------
    @staticmethod
    def campaign_key(parsed: dict) -> str:
        """Khóa campaign ổn định (dùng cả cho cooldown)."""
        src = parsed["attacker_ip"]
        if src == "UNKNOWN":
            src = f"rule:{parsed['rule_id']}"
        return f"{src}|{parsed['victim_ip']}"

    # ------------------------------------------------------------------
    def add(self, parsed: dict) -> None:
        """
        Ghi nhận một alert. KHÔNG xả ngay: gọi collect_ready() sau khi đã nạp
        hết lô alert của vòng polling để nhóm chứa đủ bằng chứng.
        """
        key = self.campaign_key(parsed)
        if is_brute_force_alert(parsed):
            self._add_brute_force(key, parsed)
            return
        group = self._groups.setdefault(key, {"first": self.clock(), "alerts": []})
        group["alerts"].append(parsed)

    def _add_brute_force(self, key: str, parsed: dict) -> None:
        now = self.clock()
        events = self._bf[key]
        events.append((alert_event_time(parsed), parsed))

        # Cửa sổ trượt: chỉ giữ sự kiện trong bf_window giây gần nhất (theo
        # thời gian SỰ KIỆN, nên batch trễ từ Indexer vẫn đếm đúng).
        newest = max(ts for ts, _ in events)
        events[:] = [(ts, p) for ts, p in events if newest - ts <= self.bf_window]
        self._bf_touched[key] = now

        count = len(events)
        if self.composite_trigger and is_composite_brute_force(parsed):
            self._bf_triggered[key] = "rule tổng hợp của Wazuh"
        elif count > self.bf_threshold and key not in self._bf_triggered:
            self._bf_triggered[key] = f"{count} > ngưỡng {self.bf_threshold}"
        elif key not in self._bf_triggered:
            logger.info(
                "[BRUTE-FORCE] Đang theo dõi %d/%d alert đăng nhập lỗi từ %s",
                count, self.bf_threshold, key,
            )

    # ------------------------------------------------------------------
    def collect_ready(self) -> list[Group]:
        """
        [Lỗi 2] Gọi mỗi vòng polling SAU KHI đã nạp hết lô alert:
          - xả brute-force đã đạt điều kiện kích hoạt (gồm cả alert đến sau);
          - xả mọi nhóm thường đã hết cửa sổ gom theo ĐỒNG HỒ, kể cả khi vòng
            này không có alert mới;
          - dọn bộ đếm brute-force im lặng quá lâu (tránh rò rỉ bộ nhớ).
        """
        now = self.clock()
        ready: list[Group] = []

        for key, reason in list(self._bf_triggered.items()):
            alerts = [p for _, p in self._bf.pop(key, [])]
            self._bf_touched.pop(key, None)
            del self._bf_triggered[key]
            if alerts:
                logger.info("[BRUTE-FORCE] Kích hoạt (%s): %d alert từ %s trong cửa sổ %ds",
                            reason, len(alerts), key, self.bf_window)
                ready.append((key, alerts))

        for key in [k for k, g in self._groups.items()
                    if now - g["first"] >= self.group_window]:
            alerts = self._groups.pop(key)["alerts"]
            logger.info("[GROUP] Hết cửa sổ %ds → xả %d alert của %s",
                        self.group_window, len(alerts), key)
            ready.append((key, alerts))

        stale_after = max(self.bf_window * 5, 300)
        for key in [k for k, t in self._bf_touched.items() if now - t > stale_after]:
            logger.debug("[BRUTE-FORCE] Bỏ bộ đếm im lặng: %s (%d alert, dưới ngưỡng)",
                         key, len(self._bf.get(key, [])))
            self._bf.pop(key, None)
            self._bf_touched.pop(key, None)

        return ready

    def pending(self) -> dict:
        """Số lượng đang chờ (dùng cho log/kiểm thử)."""
        return {
            "groups": {k: len(g["alerts"]) for k, g in self._groups.items()},
            "brute_force": {k: len(v) for k, v in self._bf.items()},
        }
