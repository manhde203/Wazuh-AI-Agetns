import json
import asyncio
import hmac
import html
import logging
import os
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from crewai import Agent, Task, Crew, LLM

# Import các Tools vừa tạo
from tools.threat_intel import query_threat_intel
from tools.asset_db import query_asset_db

load_dotenv()
app = FastAPI()
pipeline_lock = asyncio.Lock()

# ==========================================
# CẤU HÌNH HỆ THỐNG
# ==========================================
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
# Token bảo vệ webhook: Wazuh gửi kèm header "X-Webhook-Token" hoặc query "?token=..."
WAZUH_WEBHOOK_TOKEN = os.environ.get("WAZUH_WEBHOOK_TOKEN", "")

logger = logging.getLogger("soc_agent.webhook")
if not WAZUH_WEBHOOK_TOKEN:
    logger.warning("WAZUH_WEBHOOK_TOKEN chưa đặt — webhook /wazuh-alert KHÔNG được xác thực!")

ollama_llm = LLM(
    model="ollama/llama3.2",
    base_url="http://localhost:11434"
)

# ==========================================
# ĐỊNH NGHĨA MULTI-AGENT (PROMPT TIẾNG ANH)
# ==========================================
analyst_agent = Agent(
    role="L1 Security Operations Center (SOC) Analyst",
    goal="Investigate Wazuh SIEM alerts, extract the Source IP, and ALWAYS use the Threat Intelligence tool to determine if the attacker is a known threat.",
    backstory="You are a meticulous digital forensics expert. You NEVER guess or invent data. Before drawing conclusions about an attacker, you strictly use your 'Query Threat Intelligence' tool to verify their reputation.",
    verbose=True,
    tools=[query_threat_intel],
    llm=ollama_llm
)

responder_agent = Agent(
    role="Incident Response (IR) Commander",
    goal="Identify the victim IP, use the Asset Database tool to assess the system's criticality, and formulate a final mitigation strategy.",
    backstory="You are the head of the Blue Team. You ALWAYS use your 'Query Asset Database' tool to check how important the attacked machine is. If a Tier 1 server is attacked, you demand immediate network isolation.",
    verbose=True,
    tools=[query_asset_db],
    llm=ollama_llm
)

async def send_to_telegram(case_id, title, final_output):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    header = (
        f"🚨 <b>[CASE SOAR MULTI-AGENT] - {html.escape(str(title))}</b>\n"
        f"-----------------------------------------\n"
        f"📌 <b>Case ID:</b> #INCIDENT_{html.escape(str(case_id))}\n"
        f"-----------------------------------------\n"
    )
    # Cắt văn bản gốc TRƯỚC khi escape để không cắt giữa entity '&amp;'
    max_body = 4096 - len(header) - len("\n…[đã rút gọn]")
    parts, used = [], 0
    for ch in str(final_output):
        esc = html.escape(ch)
        if used + len(esc) > max_body:
            parts.append("\n…[đã rút gọn]")
            break
        parts.append(esc)
        used += len(esc)
    safe_body = "".join(parts)
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url,
                json={"chat_id": TELEGRAM_CHAT_ID, "text": header + safe_body, "parse_mode": "HTML"},
                timeout=10,
            )
            resp.raise_for_status()
    except Exception as e:  # noqa: BLE001
        logger.error("Gửi Telegram thất bại: %s", e)


def _authorized(request: Request) -> bool:
    if not WAZUH_WEBHOOK_TOKEN:
        return True
    supplied = request.headers.get("X-Webhook-Token") or request.query_params.get("token") or ""
    return hmac.compare_digest(supplied, WAZUH_WEBHOOK_TOKEN)

# ==========================================
# CỔNG NHẬN LOG TỪ WAZUH (FASTAPI)
# ==========================================
@app.post("/wazuh-alert")
async def receive_alert(request: Request):
    if not _authorized(request):
        raise HTTPException(status_code=401, detail="Sai hoặc thiếu webhook token")
    try:
        alert = await request.json()
        alert_id = alert.get("id", "0000")
        rule_desc = alert.get("rule", {}).get("description", "Unknown Alert")
        
        minimal_log = {
            "attack_type": rule_desc,
            "victim_ip": (alert.get("agent") or {}).get("ip") or "UNKNOWN",
            "attacker_ip": alert.get("data", {}).get("srcip", "Unknown")
        }
        log_input = json.dumps(minimal_log, indent=2)
        
        # Giao việc cho các Agent
        task_analyze = Task(
            description=f"Analyze this SIEM log:\n{log_input}\n\n1. Extract the 'attacker_ip'.\n2. MUST USE your 'Query Threat Intelligence' tool on the attacker_ip.\n3. Write a short technical summary including the tool's result.",
            expected_output="A technical summary detailing the attack type, source IP, and its threat intelligence reputation.",
            agent=analyst_agent
        )
        
        task_respond = Task(
            description=f"Based on the Analyst's summary and the victim_ip ({minimal_log['victim_ip']}):\n1. MUST USE your 'Query Asset Database' tool on the victim_ip to check its business value.\n2. Write a professional incident response alert.\n\nCRITICAL RULE: The final output MUST be entirely translated and written in VIETNAMESE.",
            expected_output="A complete, actionable incident response alert written in Vietnamese, including Threat Intel findings and Asset Criticality.",
            agent=responder_agent
        )
        
        soar_crew = Crew(agents=[analyst_agent, responder_agent], tasks=[task_analyze, task_respond], verbose=True)
        # CrewAI không cho phép dùng cùng executor đồng thời từ nhiều request.
        if pipeline_lock.locked():
            raise HTTPException(status_code=429, detail="Pipeline AI đang xử lý request khác")
        async with pipeline_lock:
            crew_result = await soar_crew.kickoff_async()
        
        await send_to_telegram(alert_id, rule_desc, crew_result.raw)
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline xử lý thất bại: {e}") from e

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)