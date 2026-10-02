# SOC SOAR Agent with Wazuh

Agent hỗ trợ phân tích alert Wazuh: polling alert từ Indexer, lọc và gom campaign, phân tích bằng CrewAI + Ollama, tra cứu AbuseIPDB, tạo báo cáo và gửi Telegram.

## Luồng xử lý

```text
Wazuh Agent -> Wazuh Manager -> Wazuh Indexer (:9200)
    -> main.py: polling, lọc, dedup và gom campaign
    -> pipeline.py: baseline, threat intelligence, asset context, phân tích AI
    -> báo cáo TXT/JSON -> Telegram
```

`main.py` dùng cho polling thực tế. `demo.py` tạo alert mẫu trong bộ nhớ để thử pipeline; demo không kết nối Wazuh và không tạo traffic tấn công.

## Yêu cầu

- Python 3.10+
- Wazuh Manager API qua HTTPS, mặc định cổng `55000`
- Wazuh Indexer/OpenSearch qua HTTPS, mặc định cổng `9200`
- Ollama đang chạy cục bộ, nếu bật AI
- Bot Telegram và chat ID, nếu muốn nhận thông báo
- AbuseIPDB API key tùy chọn

## Cài đặt trên Windows PowerShell

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install crewai httpx python-dotenv fastapi "uvicorn[standard]" requests
Copy-Item env.example .env
```

Điền thông tin thật vào `.env`. Không đưa file này hoặc token/API key lên GitHub. Cập nhật IP/tài sản mẫu trong `tools/asset_db.py` và danh sách baseline trong `tools/baseline.py` trước khi vận hành.

## Kiểm tra và chạy

Kiểm tra kết nối trước:

```powershell
python testconnect.py
```

Chạy polling:

```powershell
python main.py
```

Dừng bằng `Ctrl+C`. Mặc định chương trình bắt đầu từ alert mới tại thời điểm khởi động.

## Demo và kiểm thử

```powershell
python demo.py --scenario brute --no-llm
python demo.py --scenario internal --no-llm
python demo.py --scenario web --no-llm
python demo.py --scenario fp --no-llm
python demo.py --scenario inject --no-llm
python test_soc_logic.py
```

Các scenario minh họa brute-force SSH, SQL injection, false positive và prompt injection. `--no-llm` tắt AI và dùng kết quả dự phòng theo rule.

## Cấu hình chính

- `WAZUH_HOST`, `WAZUH_USER`, `WAZUH_PASSWORD`: Wazuh Manager.
- `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`: quyền đọc Indexer.
- `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`: gửi thông báo.
- `ABUSEIPDB_API_KEY`: tra uy tín IP công cộng; IP nội bộ không được gửi lên dịch vụ.
- `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `AI_ENABLED`: cấu hình AI.
- `BRUTE_FORCE_ALERT_THRESHOLD`, `BRUTE_FORCE_WINDOW_SECONDS`: ngưỡng gom brute-force.
- `START_FROM_NOW`: bỏ qua alert lịch sử khi khởi động, mặc định `true`.

## Lưu ý

- Chỉ kiểm thử tấn công trên hệ thống bạn sở hữu hoặc được phép kiểm tra.
- Pipeline không tự chặn IP; các bước ứng phó trong báo cáo là khuyến nghị cần người vận hành xác minh.
- Rule ID Wazuh có thể khác theo phiên bản/ruleset; đối chiếu với ruleset trên Wazuh Manager của bạn.
- Báo cáo được lưu trong `reports/`.