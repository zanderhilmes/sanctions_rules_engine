"""
SnowflakeEnricher — backfills customer DOB and verification status from
APP_CASH.HEALTH.IDENTITY_IDV_ATTEMPTS before the rule engine runs.

Lookup: alert.account_id → ACCOUNT_ID column (see _ACCOUNT_ID_COL below).

Fields populated on Alert:
    customer_dob        — BIRTH_YEAR as a year-only string e.g. "1988"
                          enables DOB mismatch rule (F+ 1B)
    customer_verified   — True when a successful IDV attempt is on record

--------------------------------------------------------------------------------
Setup — set credentials in .env / environment:
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

_ACCOUNT_ID_COL = "CUSTOMER_TOKEN"      # joins to alert.account_id (customer token)
_TIMESTAMP_COL  = "ATTEMPT_OCCURRED_AT" # orders by most recent attempt

try:
    import snowflake.connector
    _SF_AVAILABLE = True
except ImportError:
    _SF_AVAILABLE = False


def _build_dob(
    year_raw, month_raw, day_raw
) -> Optional[str]:
    """
    Construct a DOB string from Snowflake BIRTH_YEAR / BIRTH_MONTH / BIRTH_DAY.
    All three fields are TEXT in the table.

    Returns 'YYYY-MM-DD' when all components are present and valid,
    'YYYY' when only the year is available, or None.
    """
    year: Optional[int] = None
    try:
        year = int(year_raw) if year_raw not in (None, "", "None") else None
    except (ValueError, TypeError):
        pass

    if year is None:
        return None

    try:
        month = int(month_raw) if month_raw not in (None, "", "None") else None
        day   = int(day_raw)   if day_raw   not in (None, "", "None") else None
        if month and day:
            from datetime import date as _date
            return _date(year, month, day).isoformat()
    except (ValueError, TypeError):
        pass

    return str(year)


class SnowflakeEnricher:
    """
    Enriches an Alert with DOB and IDV verification status from Snowflake.
    Degrades gracefully — any connection or query error is caught and logged.
    """

    def __init__(
        self,
        account: str,
        user: str,
        warehouse: str,
        database: str = "APP_CASH",
        schema: str = "HEALTH",
        table: str = "IDENTITY_IDV_ATTEMPTS",
        password: str = "",
        authenticator: str = "snowflake",
        token: str = "",
        timeout_seconds: int = 10,
    ) -> None:
        if not _SF_AVAILABLE:
            raise RuntimeError(
                "snowflake-connector-python is not installed. "
                "Run: pip install snowflake-connector-python"
            )
        self._table = f"{database}.{schema}.{table}"
        self._timeout = timeout_seconds

        connect_kwargs: dict = dict(
            account=account,
            user=user,
            warehouse=warehouse,
            database=database,
            schema=schema,
            authenticator=authenticator,
            login_timeout=timeout_seconds,
            network_timeout=timeout_seconds,
        )
        if authenticator == "oauth" and token:
            connect_kwargs["token"] = token
        elif authenticator not in ("externalbrowser",) and password:
            connect_kwargs["password"] = password

        self._conn = snowflake.connector.connect(**connect_kwargs)
        log.info("[snowflake] Connected to %s (authenticator=%s)", self._table, authenticator)

    def enrich(self, alert) -> None:
        """Mutates alert in-place. Never raises."""
        if not getattr(alert, "account_id", None):
            log.debug("[snowflake] Alert %s has no account_id — skipping", alert.alert_id)
            return

        dob, verified = self._lookup(alert.account_id)

        if dob is not None and not alert.customer_dob:
            alert.customer_dob = dob
            log.info(
                "[snowflake] Alert %s: backfilled customer_dob=%s from IDV record",
                alert.alert_id, dob,
            )

        if verified and not alert.customer_verified:
            alert.customer_verified = True
            log.info(
                "[snowflake] Alert %s: customer marked verified (IDV passed)",
                alert.alert_id,
            )

    def _lookup(self, account_id: str):
        """
        Returns (dob_string, is_verified) for the most recent IDV record.
        dob_string is 'YYYY-MM-DD' when day/month are available, else 'YYYY'.
        Returns (None, False) on miss or error.
        """
        query = f"""
            SELECT BIRTH_YEAR, BIRTH_MONTH, BIRTH_DAY, ATTEMPT_SUCCESSFUL
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
            log.debug("[snowflake] No IDV record found for customer_token=%s", account_id)
            return None, False

        birth_year_raw, birth_month_raw, birth_day_raw, attempt_successful = row
        dob = _build_dob(birth_year_raw, birth_month_raw, birth_day_raw)
        is_verified = bool(attempt_successful)
        return dob, is_verified

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
