"""
terminal_ui.py
--------------
Vẽ các khung viền trên terminal cho pipeline SOC.

Có 4 loại khung:
  agent   (cyan)   : AI Agent nào đang chạy + chức năng của nó
  tool    (vàng)   : tool được gọi, đầu vào và dữ liệu thu được
  result  (xanh lá): kết quả của Agent + dựa vào bằng chứng nào
  verdict (đỏ/xanh): kết luận cuối cùng (viền đôi)

Ghi chú kỹ thuật:
  - Độ rộng chữ được tính theo "độ rộng hiển thị" (tiếng Việt có dấu, ký tự
    tổ hợp, CJK/emoji) nên viền luôn thẳng hàng.
  - Ghi trực tiếp ra sys.__stdout__ để không bị CrewAI chiếm/ẩn khi nó
    redirect sys.stdout.
  - Tắt màu: đặt biến môi trường NO_COLOR=1 hoặc SOC_COLOR=0.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
import unicodedata

# ----------------------------------------------------------------------
# Khởi tạo đầu ra
# ----------------------------------------------------------------------
_out = sys.__stdout__ or sys.stdout


def init() -> None:
    """Ép UTF-8 cho console và bật ANSI trên Windows (nếu có thể)."""
    try:
        _out.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
    if os.name == "nt":
        os.system("")  # bật xử lý ANSI escape trong Windows Terminal/PowerShell


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("SOC_COLOR") == "0":
        return False
    try:
        return bool(_out.isatty())
    except Exception:
        return False


# ----------------------------------------------------------------------
# Độ rộng hiển thị & ngắt dòng
# ----------------------------------------------------------------------
def _cw(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    if unicodedata.east_asian_width(ch) in ("W", "F"):
        return 2
    return 1


def display_width(text: str) -> int:
    return sum(_cw(c) for c in unicodedata.normalize("NFC", text))


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - display_width(text))


def wrap_text(text: str, width: int) -> list[str]:
    """Ngắt dòng theo độ rộng hiển thị; tôn trọng ký tự xuống dòng có sẵn."""
    width = max(10, width)
    result: list[str] = []
    for paragraph in str(text).replace("\r", "").split("\n"):
        paragraph = unicodedata.normalize("NFC", paragraph.rstrip())
        if not paragraph:
            result.append("")
            continue
        line, line_w = "", 0
        for word in paragraph.split(" "):
            ww = display_width(word)
            if ww > width:  # từ quá dài → cắt cứng
                if line:
                    result.append(line)
                    line, line_w = "", 0
                chunk, chunk_w = "", 0
                for ch in word:
                    cw = _cw(ch)
                    if chunk_w + cw > width:
                        result.append(chunk)
                        chunk, chunk_w = "", 0
                    chunk += ch
                    chunk_w += cw
                line, line_w = chunk, chunk_w
                continue
            extra = ww if not line else ww + 1
            if line_w + extra > width:
                result.append(line)
                line, line_w = word, ww
            else:
                line = word if not line else f"{line} {word}"
                line_w += extra
        result.append(line)
    return result


# ----------------------------------------------------------------------
# Khung
# ----------------------------------------------------------------------
class _Sep:
    """Dòng kẻ ngang ngăn cách các phần trong khung."""


SEP = _Sep()

_STYLE = {
    "agent":   {"color": "36", "double": False},
    "tool":    {"color": "33", "double": False},
    "result":  {"color": "32", "double": False},
    "info":    {"color": "37", "double": False},
    "warn":    {"color": "33", "double": False},
    "attack":  {"color": "31", "double": True},
    "clean":   {"color": "32", "double": True},
}

_SINGLE = ("┌", "─", "┐", "│", "├", "┤", "└", "┘")
_DOUBLE = ("╔", "═", "╗", "║", "╠", "╣", "╚", "╝")


def box_width() -> int:
    cols = shutil.get_terminal_size((100, 24)).columns
    return max(70, min(cols - 1, 100))


def _emit(line: str) -> None:
    _out.write(line + "\n")


def _paint(line: str, code: str, on: bool, bold: bool = False) -> str:
    if not on:
        return line
    prefix = f"\x1b[1;{code}m" if bold else f"\x1b[{code}m"
    return f"{prefix}{line}\x1b[0m"


def _render_rows(rows: list, inner: int) -> list[str | None]:
    """Trả về danh sách dòng đã ngắt; None = dòng kẻ ngang."""
    labels = [
        r[0] for r in rows
        if isinstance(r, tuple) and len(r) == 2 and r[0]
    ]
    lw = min(max((display_width(l) for l in labels), default=0), 20)
    out: list[str | None] = []

    for row in rows:
        if row is SEP:
            out.append(None)
            continue
        if isinstance(row, str):
            out.extend(wrap_text(row, inner))
            continue

        label, value = row
        label = str(label)
        indent = " " * (lw + 3) if lw else ""
        body_w = inner - len(indent)

        if isinstance(value, (list, tuple)):
            out.append(f"{_pad(label, lw)} :" if lw else label)
            items = [str(v) for v in value] or ["(không có)"]
            for item in items:
                wrapped = wrap_text(item, body_w - 2)
                for i, w in enumerate(wrapped):
                    out.append(f"{indent}{'- ' if i == 0 else '  '}{w}")
        else:
            wrapped = wrap_text(str(value), body_w)
            for i, w in enumerate(wrapped):
                if i == 0:
                    head = f"{_pad(label, lw)} : " if lw else ""
                    out.append(f"{head}{w}")
                else:
                    out.append(f"{indent}{w}")
    return out


def box(kind: str, title: str, rows: list) -> None:
    """In một khung hoàn chỉnh: tiêu đề + các dòng nội dung."""
    style = _STYLE.get(kind, _STYLE["info"])
    tl, h, tr, v, ml, mr, bl, br = _DOUBLE if style["double"] else _SINGLE
    on = _color_enabled()
    code = style["color"]
    width = box_width()
    inner = width - 4

    def border(left: str, right: str) -> str:
        return _paint(left + h * (width - 2) + right, code, on)

    def line(text: str, bold: bool = False) -> str:
        body = f"{v} {_pad(text, inner)} {v}"
        return _paint(body, code, on, bold)

    _emit("")
    _emit(border(tl, tr))
    for t in wrap_text(title, inner):
        _emit(line(t, bold=True))
    _emit(border(ml, mr))
    for row in _render_rows(rows, inner):
        if row is None:
            _emit(border(ml, mr))
        else:
            _emit(line(row))
    _emit(border(bl, br))
    _out.flush()


def arrow(text: str = "") -> None:
    """Mũi tên nối giữa hai khung để thấy luồng chạy."""
    on = _color_enabled()
    label = f"  {text}" if text else ""
    _emit(_paint(f"    │\n    ▼{label}", "90", on))
    _out.flush()


def status(message: str) -> None:
    """Một dòng trạng thái ngắn (đang chạy, bỏ qua, ...)."""
    on = _color_enabled()
    stamp = time.strftime("%H:%M:%S")
    _emit(_paint(f"  [{stamp}] ▶ {message}", "90", on))
    _out.flush()


def banner(text: str) -> None:
    on = _color_enabled()
    width = box_width()
    _emit("")
    _emit(_paint("═" * width, "35", on))
    for t in wrap_text(text, width - 2):
        _emit(_paint(f" {t}", "35", on, bold=True))
    _emit(_paint("═" * width, "35", on))
    _out.flush()
