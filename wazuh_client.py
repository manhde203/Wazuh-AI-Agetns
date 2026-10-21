"""
wazuh_client.py
---------------
Wazuh 4.4+ removed the /alerts endpoint from the REST API (port 55000).
Alerts are now stored in the Wazuh Indexer (OpenSearch) on port 9200.

Architecture:
  - Fetch new alerts : POST https://<host>:9200/wazuh-alerts-*/_search
  - Uses search_after cursor to avoid re-processing old alerts
  - Authenticates with Indexer credentials (admin or readall role)
  - REST API (port 55000) is still used for agent metadata queries

Cursor modes (controlled by START_FROM_NOW env var):
  START_FROM_NOW=true  (default)
    On first startup, fast-forward the cursor to "right now" by finding
    the most recent alert in the index. Only alerts arriving AFTER startup
    are processed. Old backlog is ignored entirely.

  START_FROM_NOW=false
    Cursor starts at the beginning of the index. All historical alerts
    are processed in chronological order before reaching live alerts.
    Use this for forensic replay or initial baseline ingestion.
"""

import os
import logging
import httpx

logger = logging.getLogger(__name__)


class WazuhClient:
    def __init__(self):
        self.host = os.environ["WAZUH_HOST"]

        # REST API — port 55000 (agent info, cluster status)
        self.api_port = int(os.environ.get("WAZUH_PORT", 55000))
        self.api_user = os.environ["WAZUH_USER"]
        self.api_pass = os.environ["WAZUH_PASSWORD"]

        # Indexer — port 9200 (alert queries)
        self.idx_port = int(os.environ.get("WAZUH_INDEXER_PORT", 9200))
        self.idx_user = os.environ.get("WAZUH_INDEXER_USER", "admin")
        self.idx_pass = os.environ.get("WAZUH_INDEXER_PASSWORD", "")

        self.api_url = f"https://{self.host}:{self.api_port}"
        self.idx_url = f"https://{self.host}:{self.idx_port}"

        # JWT token cache for REST API
        self._token: str | None = None
        self._token_expires: float = 0

        # search_after cursor — set to None until initialized
        # None = not yet initialized (will be fast-forwarded on first call if START_FROM_NOW=true)
        # []   = start of index (read all historical alerts)
        # [x]  = positioned after alert x (normal operation)
        self._last_sort_values: list | None = None

        # Whether to skip historical backlog on startup (default: True)
        self._start_from_now: bool = os.environ.get("START_FROM_NOW", "true").lower() != "false"
        self._cursor_initialized: bool = False

    # ------------------------------------------------------------------
    # Cursor initialization — fast-forward to "now" on first call
    # ------------------------------------------------------------------
    async def _init_cursor(self) -> None:
        """
        Called once before the first fetch_new_alerts() poll.

        START_FROM_NOW=true (default):
          Finds the sort values of the MOST RECENT alert currently in the
          index and sets the cursor there. The next fetch_new_alerts() call
          will only return alerts that arrive AFTER this point.
          Old backlog (minutes/hours/days of historical alerts) is skipped.

        START_FROM_NOW=false:
          Leaves the cursor at None, which means OpenSearch will return
          alerts from the very beginning of the index on the first poll.
        """
        if not self._start_from_now:
            logger.info(
                "[CURSOR] START_FROM_NOW=false — starting from beginning of index. "
                "All historical alerts will be processed."
            )
            self._cursor_initialized = True
            return

        logger.info("[CURSOR] START_FROM_NOW=true — fast-forwarding cursor to current position...")

        # Query for the single most recent alert (sort DESC, size=1)
        query = {
            "size": 1,
            "sort": [{"timestamp": "desc"}, {"_id": "desc"}],
            "query": {"match_all": {}},
            "_source": ["timestamp"],  # Only need timestamp for logging
        }

        url = f"{self.idx_url}/wazuh-alerts-*/_search"
        try:
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.post(
                    url,
                    auth=(self.idx_user, self.idx_pass),
                    json=query,
                    timeout=20,
                )
                resp.raise_for_status()
        except Exception as e:
            logger.warning(
                f"[CURSOR] Could not fast-forward cursor: {e}. "
                f"Falling back to reading from beginning of index."
            )
            self._cursor_initialized = True
            return

        hits = resp.json().get("hits", {}).get("hits", [])

        if not hits:
            logger.info(
                "[CURSOR] Index is empty — no historical alerts found. "
                "Cursor set to beginning; will read all future alerts."
            )
            self._cursor_initialized = True
            return

        latest_hit = hits[0]
        latest_ts  = latest_hit.get("_source", {}).get("timestamp", "unknown")

        # IMPORTANT: The most recent alert was sorted DESC.
        # We need ASC sort values for search_after to work correctly with
        # our main query (which sorts ASC). Re-query to get the ASC sort values
        # of this same document by its _id.
        doc_id = latest_hit.get("_id", "")
        query_asc = {
            "size": 1,
            "sort": [{"timestamp": "asc"}, {"_id": "asc"}],
            "query": {"ids": {"values": [doc_id]}},
            "_source": [],
        }

        try:
            async with httpx.AsyncClient(verify=False) as client:
                resp2 = await client.post(
                    url,
                    auth=(self.idx_user, self.idx_pass),
                    json=query_asc,
                    timeout=20,
                )
                resp2.raise_for_status()
            hits2 = resp2.json().get("hits", {}).get("hits", [])
            if hits2:
                self._last_sort_values = hits2[0].get("sort")
        except Exception as e:
            logger.warning(f"[CURSOR] ASC re-query failed: {e}. Using DESC sort values as fallback.")
            # Fallback: use the DESC sort values directly (less ideal but still works
            # because OpenSearch search_after compares by value, not sort direction)
            self._last_sort_values = latest_hit.get("sort")

        total_hits = resp.json().get("hits", {}).get("total", {})
        total_count = total_hits.get("value", "?") if isinstance(total_hits, dict) else total_hits

        logger.info(
            f"[CURSOR] Fast-forward complete. "
            f"Index has {total_count} total alerts. "
            f"Skipped all alerts up to: {latest_ts}. "
            f"Cursor: {self._last_sort_values}. "
            f"Now listening for NEW alerts only."
        )
        self._cursor_initialized = True

    # ------------------------------------------------------------------
    # REST API — JWT authentication (used for /agents endpoint)
    # ------------------------------------------------------------------
    async def _get_token(self) -> str:
        import time
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.post(
                f"{self.api_url}/security/user/authenticate",
                auth=(self.api_user, self.api_pass),
                timeout=15,
            )
            resp.raise_for_status()
        self._token = resp.json()["data"]["token"]
        self._token_expires = time.time() + 900  # Token valid for 15 min
        logger.debug("Wazuh JWT token refreshed.")
        return self._token

    # ------------------------------------------------------------------
    # Indexer — fetch new alerts via OpenSearch (Wazuh 4.4+)
    # ------------------------------------------------------------------
    async def fetch_new_alerts(
        self,
        min_level: int = 7,
        limit: int = 200,
        extra_groups: list[str] | None = None,
    ) -> list[dict]:
        """
        Query the Wazuh Indexer (OpenSearch, port 9200) for new alerts.
        Uses search_after pagination so only unprocessed alerts are returned
        on each poll cycle. Returns a normalized list of alert dicts.

        On the very first call, initializes the cursor position based on
        START_FROM_NOW setting (see _init_cursor docstring).

        extra_groups: alerts whose rule.groups contains ANY of these are
        returned EVEN IF their level is below min_level. Individual failed
        logins are low level (3-5) but must be fetched to be counted as
        brute-force; filtering by level alone made the threshold unreachable.
        """
        # Initialize cursor once on first call
        if not self._cursor_initialized:
            await self._init_cursor()

        level_or_groups: list[dict] = [{"range": {"rule.level": {"gte": min_level}}}]
        if extra_groups:
            level_or_groups.append({"terms": {"rule.groups": list(extra_groups)}})

        query: dict = {
            "size": limit,
            "sort": [{"timestamp": "asc"}, {"_id": "asc"}],  # stable secondary sort
            "query": {
                "bool": {
                    "filter": [
                        {
                            "bool": {
                                "should": level_or_groups,
                                "minimum_should_match": 1,
                            }
                        }
                    ]
                }
            },
            "_source": [
                # Core metadata
                "timestamp", "location", "full_log",
                # Rule fields
                "rule.id", "rule.description", "rule.level", "rule.groups", "rule.mitre",
                # Agent (victim host)
                "agent.id", "agent.name", "agent.ip",
                # Entire data object — ensures all decoder fields are returned
                # (srcip, src_ip, remote_addr, audit.*, netflow.*, win.eventdata.*, etc.)
                "data",
            ],
        }

        # Only fetch alerts after the last processed cursor
        if self._last_sort_values:
            query["search_after"] = self._last_sort_values

        url = f"{self.idx_url}/wazuh-alerts-*/_search"

        try:
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.post(
                    url,
                    auth=(self.idx_user, self.idx_pass),
                    json=query,
                    timeout=20,
                )
                resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error(
                f"Indexer query failed: HTTP {e.response.status_code} — {e.response.text[:200]}"
            )
            return []
        except httpx.RequestError as e:
            logger.error(f"Indexer connection error: {e}")
            return []

        hits = resp.json().get("hits", {}).get("hits", [])

        if not hits:
            logger.debug("No new alerts from Wazuh Indexer.")
            return []

        # Advance the search_after cursor to the last hit
        self._last_sort_values = hits[-1].get("sort")

        # Normalize to a flat dict matching the old Wazuh REST API shape
        alerts = []
        for hit in hits:
            src = hit.get("_source", {})
            alerts.append({
                "id":        hit.get("_id", ""),
                "timestamp": src.get("timestamp", ""),
                "rule":      src.get("rule", {}),
                "agent":     src.get("agent", {}),
                "data":      src.get("data", {}),
                "full_log":  src.get("full_log", ""),
                "location":  src.get("location", ""),
            })

        logger.info(f"Fetched {len(alerts)} new alert(s) from Wazuh Indexer.")
        return alerts

    # ------------------------------------------------------------------
    # REST API — agent metadata (still uses port 55000)
    # ------------------------------------------------------------------
    async def get_agent_info(self, agent_id: str) -> dict:
        """
        Retrieve agent metadata (OS, hostname, version, status) from the
        Wazuh REST API. Used to enrich alerts with richer agent context.
        """
        token = await self._get_token()
        try:
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.get(
                    f"{self.api_url}/agents/{agent_id}",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10,
                )
                resp.raise_for_status()
        except Exception as e:
            logger.warning(f"Could not fetch agent info for {agent_id}: {e}")
            return {}
        items = resp.json().get("data", {}).get("affected_items", [])
        return items[0] if items else {}