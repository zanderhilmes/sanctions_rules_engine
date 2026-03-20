"""
SnowflakeEnricher — backfills customer DOB and verification status from
APP_CASH.HEALTH.IDENTITY_IDV_ATTEMPTS before the rule engine runs.

Lookup: alert.account_id → ACCOUNT_ID column (see _ACCOUNT_ID_COL below).

Fields populated on Alert:
    customer_dob        — BIRTH_YEAR as a year-only string e.g. "1988"
                          enables DOB mismatch rule (F+ 1B)
    customer_verified   — True when a successful IDV attempt is on record

--------------------------------------------------------------------------------
TODOs before enabling
--------------------------------------------------------------------------------
1.  Confirm the column name that stores the account/user identifier:
        _ACCOUNT_ID_COL = "ACCOUNT_ID"   ← update if different

2.  Confirm the status column and value that indicates a passed IDV check:
        _STATUS_COL   = "STATUS"         ← update if different
        _STATUS_PASS  = "PASSED"         ← update if different

3.  Confirm the timestamp column used to pick the most recent row:
        _TIMESTAMP_COL = "CREATED_AT"    ← update if different

4.  Set credentials in .env / environment:
        SNOWFLAKE_ACCOUNT   e.g. xy12345.us-east-1
        SNOWFLAKE_USER
        SNOWFLAKE_PASSWORD
        SNOWFLAKE_WAREHOUSE e.g. COMPUTE_WH
        (database and schema are hardcoded below — change via config.yaml)

5.  Enable in config.yaml:
        snowflake:
          enabled: true
--------------------------------------------------------------------------------
"""
from __future__ import annotations

import logging
from typing import Optional

log = logging.getLogger(__name__)

# ── TODO: confirm these column names against the actual table schema ──────────
_ACCOUNT_ID_COL = "ACCOUNT_ID"
_STATUS_COL     = "STATUS"
_STATUS_PASS    = "PASSED"
_TIMESTAMP_COL  = "CREATED_AT"
# ─────────────────────────────────────────────────────────────────────────────

try:
    import snowflake.connector
    _SF_AVAILABLE = True
except ImportError:
    _SF_AVAILABLE = False


class SnowflakeEnricher:
    """
    Enriches an Alert with DOB and IDV verification status from Snowflake.
    Degrades gracefully — any connection or query error is caught and logged.
    """

    def __init__(
        self,
        account: str,
        user: str,
        password: str,
        warehouse: str,
        database: str = "APP_CASH",
        schema: str = "HEALTH",
        table: str = "IDENTITY_IDV_ATTEMPTS",
        timeout_seconds: int = 10,
    ) -> None:
        if not _SF_AVAILABLE:
            raise RuntimeError(
                "snowflake-connector-python is not installed. "
                "Run: pip install snowflake-connector-python"
            )
        self._table = f"{database}.{schema}.{table}"
        self._timeout = timeout_seconds
        self._conn = snowflake.connector.connect(
            account=account,
            user=user,
            password=password,
            warehouse=warehouse,
            database=database,
            schema=schema,
            login_timeout=timeout_seconds,
            network_timeout=timeout_seconds,
        )
        log.info("[snowflake] Connected to %s", self._table)

    def enrich(self, alert) -> None:
        """Mutates alert in-place. Never raises."""
        if not getattr(alert, "account_id", None):
            log.debug("[snowflake] Alert %s has no account_id — skipping", alert.alert_id)
            return

        birth_year, verified = self._lookup(alert.account_id)

        if birth_year is not None and not alert.customer_dob:
            alert.customer_dob = str(birth_year)
            log.info(
                "[snowflake] Alert %s: backfilled customer_dob=%s from IDV record",
                alert.alert_id, alert.customer_dob,
            )

        if verified and not alert.customer_verified:
            alert.customer_verified = True
            log.info(
                "[snowflake] Alert %s: customer marked verified (IDV passed)",
                alert.alert_id,
            )

    def _lookup(self, account_id: str):
        """
        Returns (birth_year, is_verified) for the most recent IDV record.
        Returns (None, False) on miss or error.
        """
        query = f"""
            SELECT BIRTH_YEAR, {_STATUS_COL}
            FROM {self._table}
            WHERE {_ACCOUNT_ID_COL} = %s
            ORDER BY {_TIMESTAMP_COL} DESC
            LIMIT 1
        """
        try:
            cur = self._conn.cursor()
            cur.execute(query, (account_id,))
            row = cur.fetchone()
            cur.close()
        except Exception as exc:
            log.warning("[snowflake] Lookup failed for account %s: %s", account_id, exc)
            return None, False

        if row is None:
            log.debug("[snowflake] No IDV record found for account_id=%s", account_id)
            return None, False

        birth_year_raw, status = row
        birth_year: Optional[int] = None
        try:
            birth_year = int(birth_year_raw) if birth_year_raw is not None else None
        except (ValueError, TypeError):
            pass

        is_verified = isinstance(status, str) and status.upper() == _STATUS_PASS.upper()
        return birth_year, is_verified

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
