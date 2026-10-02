"""
test_connection.py — Wazuh 4.4+ (Indexer API)
"""

import asyncio
import os
import httpx
from dotenv import load_dotenv

load_dotenv()


async def test():
    host     = os.environ.get("WAZUH_HOST", "192.168.x.x")
    api_port = os.environ.get("WAZUH_PORT", "55000")
    api_user = os.environ.get("WAZUH_USER", "api_reader")
    api_pass = os.environ.get("WAZUH_PASSWORD", "")
    idx_port = os.environ.get("WAZUH_INDEXER_PORT", "9200")
    idx_user = os.environ.get("WAZUH_INDEXER_USER", "admin")
    idx_pass = os.environ.get("WAZUH_INDEXER_PASSWORD", "")

    print(f"\n{'='*55}")
    print(f"  Wazuh 4.7.5 — kiểm tra kết nối")
    print(f"{'='*55}")
    print(f"  REST API  : https://{host}:{api_port}  (agent info)")
    print(f"  Indexer   : https://{host}:{idx_port}  (alerts)")
    print(f"{'='*55}\n")

    # ------------------------------------------------------------------
    # Test 1: REST API authenticate
    # ------------------------------------------------------------------
    print("[1/3] REST API — lấy JWT token...")
    token = None
    try:
        async with httpx.AsyncClient(verify=False) as c:
            r = await c.post(
                f"https://{host}:{api_port}/security/user/authenticate",
                auth=(api_user, api_pass), timeout=10,
            )
            r.raise_for_status()
            token = r.json()["data"]["token"]
        print(f"  ✅ Token OK: {token[:30]}...\n")
    except Exception as e:
        print(f"  ❌ Lỗi: {e}\n")

    # ------------------------------------------------------------------
    # Test 2: REST API — danh sách agents
    # ------------------------------------------------------------------
    print("[2/3] REST API — danh sách agents...")
    try:
        async with httpx.AsyncClient(verify=False) as c:
            r = await c.get(
                f"https://{host}:{api_port}/agents",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 5}, timeout=10,
            )
            r.raise_for_status()
            agents = r.json()["data"]["affected_items"]
        print(f"  ✅ Tìm thấy {len(agents)} agent(s):")
        for a in agents:
            print(f"     - [{a.get('id')}] {a.get('name')} | IP: {a.get('ip')} | {a.get('status')}")
        print()
    except Exception as e:
        print(f"  ❌ Lỗi: {e}\n")

    # ------------------------------------------------------------------
    # Test 3: Indexer (port 9200) — query alerts
    # ------------------------------------------------------------------
    print("[3/3] Indexer (port 9200) — lấy 3 alert gần nhất...")

    if not idx_pass:
        print("  ⚠️  WAZUH_INDEXER_PASSWORD chưa điền trong .env!")
        print("  → Thêm vào .env rồi chạy lại.\n")
    else:
        try:
            query = {
                "size": 3,
                "sort": [{"timestamp": "desc"}],
                "query": {"range": {"rule.level": {"gte": 3}}},
                "_source": ["timestamp", "rule.level", "rule.description",
                            "agent.name", "agent.ip"]
            }
            async with httpx.AsyncClient(verify=False) as c:
                r = await c.post(
                    f"https://{host}:{idx_port}/wazuh-alerts-*/_search",
                    auth=(idx_user, idx_pass),
                    json=query, timeout=15,
                )
                r.raise_for_status()
                hits = r.json().get("hits", {}).get("hits", [])

            if hits:
                print(f"  ✅ Tìm thấy {len(hits)} alert(s):")
                for h in hits:
                    s = h["_source"]
                    print(f"     - [level {s.get('rule',{}).get('level')}] "
                          f"{s.get('rule',{}).get('description')} "
                          f"| agent: {s.get('agent',{}).get('name')} "
                          f"| {s.get('timestamp','')[:19]}")
            else:
                print("  ✅ Indexer kết nối OK — chưa có alert nào.")
            print()
        except httpx.HTTPStatusError as e:
            print(f"  ❌ HTTP {e.response.status_code}: {e.response.text[:200]}\n")
        except Exception as e:
            print(f"  ❌ Lỗi: {e}\n")

    print("="*55)
    print("  Nếu cả 3 bước ✅ → chạy: python main.py")
    print("="*55 + "\n")


if __name__ == "__main__":
    asyncio.run(test())