import requests

mock_alert = {
    "id": "1002",
    "rule": {"description": "sshd: brute force trying to get access to the system."},
    "agent": {"name": "victim-ubuntu", "ip": "192.168.1.30"},
    "data": {"srcip": "192.168.1.10", "dstuser": "admin"}
}

try:
    response = requests.post("http://127.0.0.1:8000/wazuh-alert", json=mock_alert)
    print("Trạng thái:", response.json())
except Exception as e:
    print("Lỗi:", e)