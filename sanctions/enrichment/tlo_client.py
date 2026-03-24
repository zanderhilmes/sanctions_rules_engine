"""
TLOxp enrichment client.

TLOxp (LexisNexis Risk Solutions) is an identity-verification and
people-search platform used to look up customer DOB, address, and name
variants when that information is missing from the screening alert.

Pipeline role:
    SnowflakeEnricher → OFACEnricher → TLOxpEnricher → RuleRegistry

What it populates on Alert (when a record is found):
    alert.customer_dob      — fills gap when screening system has no DOB
    alert.customer_state    — confirms/fills state from TLO address history
    alert.customer_verified — True when TLO returns a confident identity match
    alert.tlo_hit           — True/False/None (hit / not found / not queried)
    alert.tlo_dob           — raw DOB string from TLO response
    alert.tlo_state         — raw state from TLO response

--------------------------------------------------------------------------------
INTEGRATION NOTES — fill in before enabling
--------------------------------------------------------------------------------
TLOxp uses a REST/JSON API provisioned by your LexisNexis account rep.
You will need:
  1. api_key  — your TLOxp API key (set via TLOXP_API_KEY env var)
  2. api_url  — base URL from your contract, e.g.
                "https://api.tlo.com/v3"  (verify with LexisNexis)

Typical search endpoint:
    POST {api_url}/search/person
    Headers: {"Authorization": "Bearer {api_key}", "Content-Type": "application/json"}
    Body:    {"firstName": ..., "lastName": ..., "zip": ..., "state": ...}

Typical response shape (verify against your contract's schema):
    {
      "records": [
        {
          "dob": "YYYY-MM-DD",
          "firstName": "...",
          "lastName": "...",
          "addresses": [{"state": "CA", "zip": "90210"}],
          "confidence": 0.92
        }
      ]
    }

Steps to activate:
  1. Set TLOXP_API_KEY and TLOXP_API_URL in your .env
  2. Set tlo.enabled: true in config.yaml
  3. Fill in _SEARCH_ENDPOINT and _parse_response() below to match your schema
  4. Run: python3 main.py --input your_batch.csv
     and confirm [tlo] log lines show correct lookups
--------------------------------------------------------------------------------
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

import requests

log = logging.getLogger(__name__)

# ── TODO: update to match your LexisNexis contract ───────────────────────────
_SEARCH_ENDPOINT = "/search/person"   # relative to api_url
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class TLOResult:
    """Structured result from a TLOxp person search."""
    found: bool
    dob: Optional[str] = None           # "YYYY-MM-DD" or None
    state: Optional[str] = None         # Two-letter US state code
    verified_name: Optional[str] = None # Full name as returned by TLO
    confidence: float = 0.0             # 0.0–1.0 match confidence from TLO
    raw: Optional[dict] = None          # Full raw response record for debugging


class TLOxpClient:
    """
    Lightweight TLOxp REST client with retry logic and graceful degradation.

    All network failures are caught and logged; the pipeline continues
    without TLO data rather than failing an alert.
    """

    def __init__(
        self,
        api_key: str,
        api_url: str,
        timeout_seconds: int = 10,
        max_retries: int = 2,
    ) -> None:
        self._api_key = api_key
        self._base_url = api_url.rstrip("/")
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def lookup(
        self,
        full_name: str,
        zip_code: Optional[str] = None,
        state: Optional[str] = None,
    ) -> Optional[TLOResult]:
        """
        Search TLOxp for a person by name and optional location.

        Returns a TLOResult, or None if the request failed entirely.
        Returns TLOResult(found=False) if TLO responded but found no records.
        """
        parts = full_name.strip().split(None, 1)
        first = parts[0] if parts else full_name
        last = parts[1] if len(parts) > 1 else ""

        payload: dict = {"firstName": first, "lastName": last}
        if zip_code:
            payload["zip"] = zip_code
        if state:
            payload["state"] = state

        raw_response = self._post(_SEARCH_ENDPOINT, payload)
        if raw_response is None:
            return None  # Network/auth error — logged already

        return self._parse_response(raw_response)

    def _post(self, endpoint: str, payload: dict) -> Optional[dict]:
        url = f"{self._base_url}{endpoint}"
        for attempt in range(1, self._max_retries + 1):
            try:
                resp = self._session.post(url, json=payload, timeout=self._timeout)
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.Timeout:
                log.warning("[tlo] Timeout on attempt %d/%d for %s",
                            attempt, self._max_retries, url)
            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response else "?"
                log.warning("[tlo] HTTP %s on attempt %d/%d: %s",
                            status, attempt, self._max_retries, exc)
                if status in (400, 401, 403):
                    break  # Don't retry auth/bad-request errors
            except requests.exceptions.RequestException as exc:
                log.warning("[tlo] Request error on attempt %d/%d: %s",
                            attempt, self._max_retries, exc)
            if attempt < self._max_retries:
                time.sleep(0.5 * attempt)

        log.error("[tlo] All %d attempts failed for %s", self._max_retries, url)
        return None

    @staticmethod
    def _parse_response(data: dict) -> TLOResult:
        """
        Parse the TLOxp JSON response into a TLOResult.

        ── TODO: update field paths to match your contract schema ──────────────
        The field names below match a common LexisNexis REST shape.
        Your contract may differ — check the API reference your account rep
        provides and update the key names accordingly.
        ────────────────────────────────────────────────────────────────────────
        """
        records = data.get("records") or data.get("results") or []
        if not records:
            return TLOResult(found=False)

        # Take the highest-confidence record
        best = max(records, key=lambda r: float(r.get("confidence", 0)), default=records[0])

        # ── TODO: verify these field paths against your schema ──
        dob: Optional[str] = (
            best.get("dob")
            or best.get("dateOfBirth")
            or best.get("birthDate")
        )

        state: Optional[str] = None
        addresses = best.get("addresses") or best.get("address") or []
        if isinstance(addresses, list) and addresses:
            state = addresses[0].get("state") or addresses[0].get("stateCode")
        elif isinstance(addresses, dict):
            state = addresses.get("state") or addresses.get("stateCode")

        first = best.get("firstName", "")
        last = best.get("lastName", "")
        verified_name = f"{first} {last}".strip() or None
        confidence = float(best.get("confidence", 0.5))
        # ── end TODO ──

        return TLOResult(
            found=True,
            dob=dob,
            state=state,
            verified_name=verified_name,
            confidence=confidence,
            raw=best,
        )


class TLOxpEnricher:
    """
    Pipeline enrichment step: calls TLOxp and backfills missing Alert fields.

    Only queries TLO when customer_dob is missing (primary use case — enables
    the DOB mismatch rule) or customer_state is missing.

    A TLO lookup that returns no record is noted via tlo_hit=False — it is a
    weak clearing signal for the LLM but does not auto-clear on its own.
    """

    _MIN_CONFIDENCE = 0.70  # Below this TLO DOB/state are not used

    def __init__(self, client: TLOxpClient) -> None:
        self._client = client

    def enrich(self, alert) -> None:
        """Mutates alert in-place with TLO data. Never raises."""
        needs_dob = not alert.customer_dob
        needs_state = not alert.customer_state

        if not (needs_dob or needs_state):
            return

        log.debug("[tlo] Querying for alert %s — %s (zip=%s)",
                  alert.alert_id, alert.customer_name, alert.zip_code)

        result = self._client.lookup(
            full_name=alert.customer_name,
            zip_code=alert.zip_code,
            state=alert.customer_state,
        )

        if result is None:
            log.warning("[tlo] Alert %s: request failed, continuing without TLO data",
                        alert.alert_id)
            return

        alert.tlo_hit = result.found

        if not result.found:
            log.info("[tlo] Alert %s: no record found for '%s'",
                     alert.alert_id, alert.customer_name)
            return

        log.info("[tlo] Alert %s: hit for '%s' (confidence=%.2f)",
                 alert.alert_id, alert.customer_name, result.confidence)

        if result.confidence < self._MIN_CONFIDENCE:
            log.info("[tlo] Alert %s: confidence %.2f below threshold — not using DOB/state",
                     alert.alert_id, result.confidence)
            return

        if needs_dob and result.dob:
            alert.customer_dob = result.dob
            alert.tlo_dob = result.dob
            alert.customer_verified = True
            log.info("[tlo] Alert %s: backfilled customer_dob=%s", alert.alert_id, result.dob)

        if needs_state and result.state:
            alert.customer_state = result.state
            alert.tlo_state = result.state
            log.info("[tlo] Alert %s: backfilled customer_state=%s", alert.alert_id, result.state)
