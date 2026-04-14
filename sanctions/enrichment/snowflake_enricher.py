"""
SnowflakeEnricher — backfills customer DOB and verification status from
Snowflake before the rule engine runs.

DOB lookup order (first hit wins):
  1. APP_CASH.HEALTH.IDENTITY_DOB_HISTORY  — most reliable; has full DOB DATE column
     (the source that populates CASH_W_DOB on CASH_CUSTOMER_IDENTITY_W_AFTERPAY)
  2. APP_CASH.HEALTH.IDENTITY_IDV_ATTEMPTS — fallback; only present after IDV completion
  3. APP_CASH.APP.CUSTOMER_SUMMARY         — BIRTH_YEAR only; last resort

Fields populated on Alert:
    customer_dob        — 'YYYY-MM-DD' or 'YYYY' string; enables DOB mismatch rule (F+ 1B)
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
_DEFAULT_ACCOUNT_ID_COL = "CUSTOMER_TOKEN"

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
        account_table: str = "",
        account_id_col: str = "CUSTOMER_TOKEN",
        account_created_col: str = "CREATED_AT",
        dob_history_table: str = "APP_CASH.HEALTH.IDENTITY_DOB_HISTORY",
        customer_summary_table: str = "APP_CASH.APP.CUSTOMER_SUMMARY",
    ) -> None:
        if not _SF_AVAILABLE:
            raise RuntimeError(
                "snowflake-connector-python is not installed. "
                "Run: pip install snowflake-connector-python"
            )
        self._table = f"{database}.{schema}.{table}"
        self._timeout = timeout_seconds
        self._account_table = account_table or ""
        self._account_id_col = account_id_col
        self._account_created_col = account_created_col
        self._dob_history_table = dob_history_table or ""
        self._customer_summary_table = customer_summary_table or ""

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
        # Explicitly activate the warehouse — browser-based auth doesn't always inherit it
        if warehouse:
            cur = self._conn.cursor()
            cur.execute(f'USE WAREHOUSE "{warehouse}"')
            cur.close()
        log.info("[snowflake] Connected to %s (authenticator=%s)", self._table, authenticator)

    def enrich(self, alert) -> None:
        """Mutates alert in-place. Never raises."""
        if not getattr(alert, "account_id", None):
            log.debug("[snowflake] Alert %s has no account_id — skipping", alert.alert_id)
            return

        # ---- DOB from IDENTITY_DOB_HISTORY (primary source) ----
        if self._dob_history_table and not alert.customer_dob:
            dob = self._lookup_dob_history(alert.account_id)
            if dob is not None:
                alert.customer_dob = dob
                log.info(
                    "[snowflake] Alert %s: backfilled customer_dob=%s from DOB history",
                    alert.alert_id, dob,
                )

        # ---- DOB + verified from IDENTITY_IDV_ATTEMPTS (fallback) ----
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

        # ---- DOB from CUSTOMER_SUMMARY.BIRTH_YEAR (last resort) ----
        if self._customer_summary_table and not alert.customer_dob:
            dob = self._lookup_customer_summary(alert.account_id)
            if dob is not None:
                alert.customer_dob = dob
                log.info(
                    "[snowflake] Alert %s: backfilled customer_dob=%s from CUSTOMER_SUMMARY",
                    alert.alert_id, dob,
                )

        # Account creation date — only when table is configured
        if self._account_table and not getattr(alert, "account_created_at", None):
            created_at = self._lookup_account_created(alert.account_id)
            if created_at:
                alert.account_created_at = created_at
                log.info(
                    "[snowflake] Alert %s: backfilled account_created_at=%s",
                    alert.alert_id, created_at,
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

    def _lookup_dob_history(self, account_id: str) -> Optional[str]:
        """
        Return customer DOB from IDENTITY_DOB_HISTORY — the table that backs
        CASH_W_DOB on CASH_CUSTOMER_IDENTITY_W_AFTERPAY.

        Prefers the DOB DATE column (full date); falls back to BIRTH_YEAR/MONTH/DAY
        text columns if DOB is NULL.  Returns 'YYYY-MM-DD' or 'YYYY', or None.
        """
        query = (
            "SELECT DOB, BIRTH_YEAR, BIRTH_MONTH, BIRTH_DAY "
            "FROM " + self._dob_history_table + " "
            "WHERE CUSTOMER_TOKEN = %s "
            "ORDER BY START_TIME DESC "
            "LIMIT 1"
        )
        try:
            cur = self._conn.cursor()
            cur.execute(query, (account_id,))
            row = cur.fetchone()
            cur.close()
        except Exception as exc:
            log.warning("[snowflake] DOB history lookup failed for %s: %s", account_id, exc)
            return None

        if row is None:
            log.debug("[snowflake] No DOB history record for customer_token=%s", account_id)
            return None

        dob_raw, birth_year_raw, birth_month_raw, birth_day_raw = row

        # DOB column is a DATE — Snowflake returns it as a Python date object
        if dob_raw is not None:
            try:
                from datetime import date as _date, datetime as _dt
                if isinstance(dob_raw, (_date, _dt)):
                    return dob_raw.strftime("%Y-%m-%d")
                s = str(dob_raw)[:10]
                if len(s) == 10:
                    return s
            except Exception:
                pass

        # Fallback to text columns
        return _build_dob(birth_year_raw, birth_month_raw, birth_day_raw)

    def _lookup_customer_summary(self, account_id: str) -> Optional[str]:
        """
        Return customer DOB from CUSTOMER_SUMMARY.BIRTH_YEAR — year-only last resort.
        Returns 'YYYY' string, or None on miss/error.
        """
        query = (
            "SELECT BIRTH_YEAR "
            "FROM " + self._customer_summary_table + " "
            "WHERE CUSTOMER_TOKEN = %s "
            "LIMIT 1"
        )
        try:
            cur = self._conn.cursor()
            cur.execute(query, (account_id,))
            row = cur.fetchone()
            cur.close()
        except Exception as exc:
            log.warning("[snowflake] CUSTOMER_SUMMARY lookup failed for %s: %s", account_id, exc)
            return None

        if row is None or row[0] is None:
            log.debug("[snowflake] No BIRTH_YEAR in CUSTOMER_SUMMARY for customer_token=%s", account_id)
            return None

        return _build_dob(row[0], None, None)  # year-only → 'YYYY'

    def _lookup_account_created(self, account_id: str) -> Optional[str]:
        """
        Return the account creation date as 'YYYY-MM-DD', or None on miss/error.

        Configure via snowflake.account_table in config.yaml, e.g.:
            account_table: "APP_CASH.CORE.SELLERS"
            account_id_col: "CUSTOMER_TOKEN"
            account_created_col: "CREATED_AT"
        """
        query = f"""
            SELECT {self._account_created_col}
            FROM {self._account_table}
            WHERE {self._account_id_col} = %s
            LIMIT 1
        """
        try:
            cur = self._conn.cursor()
            cur.execute(query, (account_id,))
            row = cur.fetchone()
            cur.close()
        except Exception as exc:
            log.warning("[snowflake] Account creation lookup failed for %s: %s", account_id, exc)
            return None

        if row is None or row[0] is None:
            return None

        created = row[0]
        # Snowflake may return a datetime object or a string
        try:
            from datetime import date as _date, datetime as _dt
            if isinstance(created, (_date, _dt)):
                return created.strftime("%Y-%m-%d")
            return str(created)[:10]  # Trim timestamp to date
        except Exception:
            return str(created)[:10]

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
