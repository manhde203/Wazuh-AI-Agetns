# SOC SOAR Agent with Wazuh

Tự động thu thập alert từ Wazuh, lọc nhiễu/gom nhóm sự kiện, phân tích bằng CrewAI + Ollama, tra cứu AbuseIPDB và gửi thông báo sự cố qua Telegram.

## Kiến trúc

```
Wazuh Indexer (9200) -> main.py polling -> lọc / khử trùng / FP nhanh (không LLM)
                     -> grouping.py: đếm brute-force (cửa sổ trượt) + gom campaign
                     -> pipeline.py: 4 AI Agent (CrewAI + Ollama), mỗi agent một khung terminal
                           Agent 1  FP Classifier      <- tool Check Baseline
                           Agent 2  L1 SOC Analyst     <- tool Query Threat Intelligence
                           Agent 3  IR Commander       <- tool Query Asset Database + ma trận ưu tiên
                           Agent 4  Incident Reporter  <- tổng hợp kết quả đã kiểm định
                     -> KẾT LUẬN (terminal + reports/*.txt + reports/*.json) -> Telegram
```

`main.py` là chương trình nên dùng trong vận hành. `ai_agent_soc.py` là API webhook FastAPI đơn giản hơn, hữu ích khi demo/tích hợp alert đẩy trực tiếp. `testconnect.py` dùng để kiểm tra kết nối Wazuh; `test_trigger.py` gửi alert mẫu vào webhook.

## Yêu cầu

- Python 3.10 hoặc mới hơn
- Wazuh Manager API có thể truy cập qua HTTPS (mặc định cổng `55000`)
- Wazuh Indexer/OpenSearch có thể truy cập qua HTTPS (mặc định cổng `9200`)
- [Ollama](https://ollama.com/) đang chạy cục bộ
- Bot Telegram và chat ID nhận thông báo
- Tùy chọn: API key AbuseIPDB cho tra cứu danh tiếng IP

## Cài đặt

Thực hiện trong PowerShell tại thư mục dự án:

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install crewai httpx python-dotenv fastapi "uvicorn[standard]" requests
Copy-Item env.example .env
```

Nếu PowerShell chặn script kích hoạt môi trường, chỉ cần cho phép trong phiên terminal hiện tại:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Sau đó cài Ollama và tải model khớp với `OLLAMA_MODEL` trong `.env`:

```powershell
ollama pull llama3.2
ollama serve
```

`ollama serve` thường đã chạy nền sau khi cài Ollama. Giữ một terminal riêng nếu bạn chạy lệnh này thủ công.

## Cấu hình

Mở `.env` và thay toàn bộ giá trị mẫu. Các biến bắt buộc khi chạy `main.py` là:

| Biến | Ý nghĩa |
| --- | --- |
| `WAZUH_HOST` | IP/DNS của Wazuh Manager và Indexer |
| `WAZUH_USER`, `WAZUH_PASSWORD` | Tài khoản REST API Wazuh |
| `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD` | Tài khoản Indexer có quyền đọc `wazuh-alerts-*` |
| `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID` | Thông tin bot Telegram |

Tùy chọn quan trọng:

- `ABUSEIPDB_API_KEY`: để trống nếu không dùng threat intelligence; pipeline vẫn chạy với mức rủi ro `UNKNOWN`.
- `OLLAMA_BASE_URL` (mặc định `http://localhost:11434`) và `OLLAMA_MODEL` (mặc định `ollama/llama3.2`).
- `START_FROM_NOW=true`: bỏ qua alert lịch sử khi khởi động; đặt `false` chỉ khi muốn replay/forensic alert cũ.
- `POLL_INTERVAL_SECONDS`, `MIN_ALERT_LEVEL`, `DEDUP_WINDOW_MINUTES`, `ALERT_GROUP_WINDOW_SECONDS`: tinh chỉnh nhịp lấy dữ liệu và giảm nhiễu.
- `BRUTE_FORCE_ALERT_THRESHOLD` (mặc định `20`), `BRUTE_FORCE_WINDOW_SECONDS` (mặc định `60`): ngưỡng theo cửa sổ trượt; `BRUTE_FORCE_COMPOSITE_TRIGGER=true` cho phép rule tổng hợp của Wazuh kích hoạt ngay. Hệ thống tự lấy cả alert đăng nhập thất bại level thấp để đếm.
- `AI_ENABLED`, `AGENT_TIMEOUT_SECONDS`, `FETCH_LIMIT`, `NOTIFY_SUPPRESSED`, `REPORT_DIR`: xem `env.example`.
- `FP_SUPPRESSION_THRESHOLD`: độ tin cậy false-positive từ đó alert sẽ bị tự ẩn.

Không commit `.env`. Tệp này chứa mật khẩu, token Telegram và API key.

Trước khi chạy thật, hãy cập nhật dữ liệu lab/hạ tầng trong `tools/asset_db.py` và các baseline, scanner IP được tin cậy trong `tools/baseline.py`.

## Kiểm tra và chạy

Kiểm tra REST API, Indexer và danh sách alert gần nhất:

```powershell
python testconnect.py
```

Nếu cả ba kiểm tra thành công, khởi động pipeline polling:

```powershell
python main.py
```

Chương trình chỉ xử lý alert mới sau khi khởi động với cấu hình mặc định. Dùng `Ctrl+C` để dừng.

## Pipeline 4 AI Agent và giao diện terminal

Mỗi nhóm cảnh báo hiển thị tuần tự: khung **Agent** (chức năng) → khung **Tool** (đầu vào, dữ liệu thu được) → khung **Kết quả** của agent (kết luận, "dựa vào", lý do, nguồn kết quả) → agent kế tiếp... và cuối cùng là khung **KẾT LUẬN CUỐI CÙNG**: có phải tấn công không, loại tấn công (MITRE ATT&CK), bằng chứng, biện pháp xử lý. Bản kết luận cũng được lưu tại `reports/incident_<thời gian>_<mã>.txt` và `.json`.

Nguyên tắc thiết kế để đầu ra đáng tin:

- **Code quyết định điều quan trọng, AI phân tích và giải thích.** Việc ẩn alert (chỉ khi baseline VÀ AI cùng kết luận FP), mức ưu tiên P1-P4 (ma trận theo Tier tài sản và RISK_TIER) và kết luận có/không là tấn công đều do code chốt dựa trên bằng chứng.
- **Mọi đầu ra của AI được kiểm định:** phải là JSON đúng schema; IP không có trong bằng chứng thì bị loại; MITRE ưu tiên ID do chính Wazuh gắn vào rule; mức độ nghiêm trọng không được thấp hơn mức tối thiểu theo quy tắc.
- **Có kết quả dự phòng theo quy tắc** nếu LLM lỗi/quá thời gian/trả sai định dạng. Mỗi khung ghi rõ nguồn: `AI (model) · đã kiểm định` hay `QUY TẮC DỰ PHÒNG — <lý do>`.
- **Chống prompt injection:** dữ liệu log nằm trong khối `<<<LOG_DATA ... LOG_DATA>>>`, được làm sạch, và prompt cấm làm theo chỉ thị nằm trong log.
- Pipeline **chạy tool thay cho agent** rồi đưa kết quả vào prompt, vì model nhỏ (ví dụ llama3.2 3B) gọi tool qua function-calling thiếu ổn định.

Model nhỏ viết tiếng Việt kém ổn định. Nếu cần chất lượng cao hơn, thử `OLLAMA_MODEL=ollama/qwen2.5:7b` hoặc `ollama/llama3.1:8b` và tăng `AGENT_TIMEOUT_SECONDS`.

### Chạy thử không cần Wazuh/Telegram

```powershell
python demo.py                      # brute-force SSH từ IP công cộng
python demo.py --scenario internal  # brute-force từ IP nội bộ vào máy Tier 1
python demo.py --scenario web       # SQL injection
python demo.py --scenario fp        # máy quét được phép -> false positicve //
python demo.py --scenario inject    # log chứa lệnh giả (thử prompt injection)
python demo.py --no-llm             # không python demo.pygọi AI, chỉ dùng quy tắc
python test_soc_logic.py            # bộ kiểm thử logic (không cần Wazuh/Ollama)
```

### Cấu trúc mã nguồn

| Tệp | Vai trò |
| --- | --- |
| `main.py` | Vòng polling, cooldown, Telegram |
| `alert_parser.py` | Chuẩn hóa alert, lọc nhanh, nhận diện brute-force |
| `grouping.py` | Khử trùng lặp, cửa sổ trượt brute-force, xả nhóm bằng bộ hẹn giờ |
| `pipeline.py` | 4 agent, kiểm định đầu ra AI, ma trận ưu tiên, báo cáo kết luận |
| `prompts.py` | Prompt chi tiết cho từng agent |
| `terminal_ui.py` | Khung viền terminal |
| `tools/` | Baseline, Threat Intelligence, Asset DB |

Lưu ý về brute-force: danh sách `COMPOSITE_RULE_IDS` trong `alert_parser.py` (rule tổng hợp của Wazuh) cần được đối chiếu với ruleset trên Wazuh Manager của bạn (ví dụ `/var/ossec/ruleset/rules/0095-sshd_rules.xml`) vì ID có thể khác giữa các phiên bản.

## Chế độ webhook (tùy chọn)

Để nhận alert qua HTTP thay vì polling Indexer:

```powershell
python ai_agent_soc.py
```

API lắng nghe tại `POST http://<may-chay-agent>:8000/wazuh-alert`. Khi API đang chạy cục bộ, có thể test:

```powershell
python test_trigger.py
```

`test_trigger.py` mặc định gửi tới `127.0.0.1:8000`; hãy đổi URL nếu webhook chạy trên máy khác.

## Xử lý sự cố nhanh

- `KeyError` khi khởi động: kiểm tra `.env` có nằm trong thư mục dự án và đủ các biến bắt buộc.
- Không kết nối Wazuh: kiểm tra firewall/tuyến mạng từ máy agent đến cổng `55000` và `9200`, sau đó chạy `testconnect.py`.
- Lỗi model/LLM: chạy `ollama list`, xác nhận model đã tải và `OLLAMA_BASE_URL` truy cập được.
- Không nhận Telegram: kiểm tra token/chat ID, bot đã được mở chat, và máy có thể truy cập `api.telegram.org`.
