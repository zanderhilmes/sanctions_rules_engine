"""
Pipeline processor: zip-derive → rules → (LLM?) → AuditRecord.
Accepts both CSV and JSON-lines input (auto-detected from file extension).
"""
from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import List, Optional

import pandas as pd

from sanctions.config import AppConfig
from sanctions.enrichment.snowflake_enricher import SnowflakeEnricher
from sanctions.llm.claude_client import ClaudeClient
from sanctions.models import Alert, AuditRecord, Decision, Disposition
from sanctions.rules.registry import RuleRegistry
from sanctions.rules.rule_age_improbability import AgeImprobabilityRule
from sanctions.rules.rule_alias_match import AliasMatchRule
from sanctions.rules.rule_common_name import CommonNameRule
from sanctions.rules.rule_dob_mismatch import DOBMismatchRule
from sanctions.rules.rule_geography import GeographyRule
from sanctions.rules.rule_low_score import LowScoreRule
from sanctions.rules.rule_name_components import NameComponentRule
from sanctions.rules.rule_prior_denylist import PriorDenylistRule
from sanctions.utils import zip_to_state

log = logging.getLogger(__name__)

_AUDIT_FIELDNAMES = [
    "alert_id", "customer_name", "sdn_name", "match_score", "zip_code",
    "customer_dob", "sdn_dob", "notary_hit", "tlo_hit", "customer_email",
    "sdn_type", "sdn_country", "customer_state",
    "decision", "confidence", "rule_summary",
    "llm_called", "llm_rationale", "llm_model", "processed_at",
]


class SanctionsPipeline:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

        self.registry = RuleRegistry(
            auto_clear_confidence_threshold=config.rules.auto_clear_confidence_threshold,
            escalate_hard_weight=config.rules.escalate_hard_weight,
            clear_hard_weight=config.rules.clear_hard_weight,
        )
        self.registry.register(PriorDenylistRule())
        self.registry.register(NameComponentRule())
        self.registry.register(AliasMatchRule())
        self.registry.register(DOBMismatchRule())
        self.registry.register(
            AgeImprobabilityRule(
                age_improbability_max_years=config.rules.age_improbability_max_years
            )
        )
        self.registry.register(LowScoreRule(threshold=config.rules.low_score_clear_threshold))
        self.registry.register(CommonNameRule(common_names_file=config.rules.common_names_file))
        self.registry.register(GeographyRule())

        self._snowflake: Optional[SnowflakeEnricher] = None
        sf = config.snowflake
        if sf.enabled and sf.account and not sf.account.startswith("${"):
            try:
                self._snowflake = SnowflakeEnricher(
                    account=sf.account,
                    user=sf.user,
                    warehouse=sf.warehouse,
                    database=sf.database,
                    schema=sf.schema_name,
                    table=sf.table,
                    password=sf.password,
                    authenticator=sf.authenticator,
                    token=sf.token,
                )
            except Exception as exc:
                log.warning("Snowflake enricher disabled — connection failed: %s", exc)
        elif sf.enabled:
            log.warning("Snowflake enabled in config but credentials not set — skipping")

        self._llm: Optional[ClaudeClient] = None
        if config.api_key and not config.api_key.startswith("${"):
            self._llm = ClaudeClient(
                api_key=config.api_key,
                model=config.llm.model,
                escalation_model=config.llm.escalation_model,
                strong_model_score_threshold=config.llm.strong_model_score_threshold,
                max_tokens=config.llm.max_tokens,
            )
        else:
            log.warning(
                "ANTHROPIC_API_KEY not set — PENDING alerts will be marked ESCALATE "
                "without LLM review"
            )

    def _process_alert(self, alert: Alert) -> AuditRecord:
        # Snowflake enrichment — backfills customer_dob and customer_verified
        if self._snowflake is not None:
            self._snowflake.enrich(alert)

        # Derive state from zip if enrichment didn't supply it
        if not alert.customer_state:
            alert.customer_state = zip_to_state(alert.zip_code)

        disposition: Disposition = self.registry.evaluate(alert)

        if disposition.decision == Decision.PENDING:
            if self._llm is not None:
                decision, confidence, rationale, model_used = self._llm.review(
                    alert, disposition
                )
                disposition.decision = decision
                disposition.confidence = confidence
                disposition.llm_called = True
                disposition.llm_rationale = rationale
                disposition.llm_model = model_used
            else:
                disposition.decision = Decision.ESCALATE
                disposition.llm_rationale = "No LLM available — escalated as fail-safe"

        return AuditRecord.from_alert_and_disposition(alert, disposition)

    def run(self, alerts: List[Alert]) -> List[AuditRecord]:
        records: List[AuditRecord] = []
        total = len(alerts)
        for i, alert in enumerate(alerts, start=1):
            log.info("[%d/%d] Processing alert %s — %s vs %s (score=%.1f)",
                     i, total, alert.alert_id, alert.customer_name,
                     alert.sdn_name, alert.match_score)
            try:
                record = self._process_alert(alert)
            except Exception as exc:
                log.error("Unhandled error on alert %s: %s", alert.alert_id, exc)
                record = AuditRecord(
                    alert_id=alert.alert_id,
                    customer_name=alert.customer_name,
                    sdn_name=alert.sdn_name,
                    match_score=alert.match_score,
                    zip_code=alert.zip_code,
                    sdn_type=None, sdn_country=None, customer_state=None,
                    decision=Decision.ESCALATE.value,
                    confidence=1.0,
                    rule_summary="pipeline_error",
                    llm_called=False,
                    llm_rationale=f"Pipeline error: {exc}",
                    llm_model=None,
                )
            records.append(record)
        return records

    def write_output(self, records: List[AuditRecord]) -> None:
        cfg = self.config.output
        Path(cfg.csv_path).parent.mkdir(parents=True, exist_ok=True)
        Path(cfg.json_path).parent.mkdir(parents=True, exist_ok=True)

        with open(cfg.csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=_AUDIT_FIELDNAMES)
            writer.writeheader()
            for r in records:
                row = r.model_dump()
                row["processed_at"] = row["processed_at"].isoformat()
                writer.writerow({k: row.get(k, "") for k in _AUDIT_FIELDNAMES})
        log.info("Audit CSV written: %s", cfg.csv_path)

        with open(cfg.json_path, "w", encoding="utf-8") as f:
            for r in records:
                row = r.model_dump()
                row["processed_at"] = row["processed_at"].isoformat()
                f.write(json.dumps(row) + "\n")
        log.info("Audit JSON written: %s", cfg.json_path)

    def print_summary(self, records: List[AuditRecord]) -> None:
        total = len(records)
        by_decision: dict = {}
        llm_count = 0
        for r in records:
            by_decision[r.decision] = by_decision.get(r.decision, 0) + 1
            if r.llm_called:
                llm_count += 1
        print(f"\n{'='*50}")
        print(f"  Sanctions Rules Engine Summary ({total} alerts)")
        print(f"{'='*50}")
        for decision, count in sorted(by_decision.items()):
            pct = 100.0 * count / total if total else 0
            print(f"  {decision:<15} {count:>4} ({pct:.1f}%)")
        print(f"  {'LLM calls':<15} {llm_count:>4} ({100.0*llm_count/total:.1f}%)")
        print(f"{'='*50}")
        print(f"  Output: {self.config.output.csv_path}")
        print(f"          {self.config.output.json_path}")
        print()


def load_alerts(path: str) -> List[Alert]:
    """Load alerts from a CSV or JSON-lines file (auto-detected by extension).
    Bridger CSV exports are detected automatically by column headers.
    """
    p = Path(path)
    if p.suffix.lower() == ".json":
        return _load_from_json(path)
    # Peek at the header to detect Bridger format
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                if "Alert ID" in line and "List Screening Score" in line:
                    return _load_from_bridger_csv(path)
                break
    return _load_from_csv(path)


def _load_from_csv(path: str) -> List[Alert]:
    df = pd.read_csv(path, dtype=str)
    alerts: List[Alert] = []
    for _, row in df.iterrows():
        try:
            score = float(row.get("match_score", 0))
        except (ValueError, TypeError):
            score = 0.0

        def _opt(val):
            if val is None:
                return None
            s = str(val).strip()
            return None if s in ("", "nan", "None") else s

        def _bool(val):
            if val is None:
                return None
            s = str(val).strip().lower()
            if s in ("true", "1"):
                return True
            if s in ("false", "0"):
                return False
            return None

        alerts.append(Alert(
            alert_id=str(row.get("alert_id", "")),
            customer_name=str(row.get("customer_name", "")),
            sdn_name=str(row.get("sdn_name", "")),
            match_score=score,
            zip_code=_opt(row.get("zip_code")),
            customer_dob=_opt(row.get("customer_dob")),
            sdn_dob=_opt(row.get("sdn_dob")),
            sdn_date_added=_opt(row.get("sdn_date_added")),
            sdn_type=_opt(row.get("sdn_type")),
            sdn_country=_opt(row.get("sdn_country")),
            sdn_program=_opt(row.get("sdn_program")),
            customer_state=_opt(row.get("customer_state")),
            customer_verified=bool(_bool(row.get("customer_verified")) or False),
            customer_email=_opt(row.get("customer_email")),
            customer_ssn_confirmed=bool(_bool(row.get("customer_ssn_confirmed")) or False),
            prior_sanctions_denylist=bool(_bool(row.get("prior_sanctions_denylist")) or False),
            notary_hit=_bool(row.get("notary_hit")),
            tlo_hit=_bool(row.get("tlo_hit")),
        ))
    return alerts


def _load_from_json(path: str) -> List[Alert]:
    """Load from JSON-lines format (one Alert JSON object per line)."""
    alerts: List[Alert] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            alerts.append(Alert(**data))
    return alerts


def _bridger_dob(raw: Optional[str]) -> Optional[str]:
    """
    Normalize a Bridger DOB string to a format parse_date() handles correctly.

    Bridger uses MM/DD/YYYY and masks unknown days as XX:
      '02/XX/1988'  →  '1988'          (year-only; day/month unknown)
      '02/15/1988'  →  '1988-02-15'    (full date; normalised to YYYY-MM-DD)
    """
    if not raw:
        return None
    s = raw.strip()
    if not s or s.lower() in ("", "nan", "none"):
        return None

    import re as _re

    # MM/XX/YYYY — day masked, keep year only
    m = _re.match(r"^(\d{1,2})/XX/(\d{4})$", s, _re.IGNORECASE)
    if m:
        return m.group(2)

    # MM/DD/YYYY — full date, reformat to YYYY-MM-DD to avoid DD/MM ambiguity
    m = _re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})$", s)
    if m:
        month, day, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
        try:
            from datetime import date as _date
            return _date(year, month, day).isoformat()
        except ValueError:
            pass

    return s


def _extract_customer_token(raw: Optional[str]) -> Optional[str]:
    """
    Normalize a Bridger account_id to a plain customer token.

    Cash App:  'c-abc123...'
               → 'c-abc123...'  (unchanged — already a customer token)

    Square:    'legal_entity_node-AX9UW6J1ZqQtUqTUO;be063a74-470f-4c26-b9f6-...'
               → 'AX9UW6J1ZqQtUqTUO'  (part between prefix and semicolon)
    """
    if not raw:
        return None
    if raw.startswith("legal_entity_node-"):
        token = raw[len("legal_entity_node-"):].split(";")[0].strip()
        return token or None
    return raw


def _load_from_bridger_csv(path: str) -> List[Alert]:
    """
    Load and deduplicate a Bridger CSV_Summary_Export.

    Bridger emits one row per watchlist source (OFAC SDN, WorldCompliance, etc.)
    for the same alert, so we deduplicate on Alert ID — keeping the OFAC SDN
    row when present, otherwise the first row seen.

    Column mapping:
        Alert ID             → alert_id
        Name                 → customer_name
        Entity Name          → sdn_name
        Best Match           → added to sdn_aliases (when different from Entity Name)
        List Screening Score → match_score
        DOB                  → customer_dob  (XX-day normalised to year-only)
        SSN                  → customer_ssn_confirmed (True when non-empty)
        File                 → sdn_program
    """
    df = pd.read_csv(path, dtype=str, skip_blank_lines=True)
    df = df.dropna(subset=["Alert ID"])

    def _opt(val) -> Optional[str]:
        if val is None:
            return None
        s = str(val).strip()
        return None if s in ("", "nan", "None") else s

    # Deduplicate: prefer OFAC SDN row; fall back to first occurrence
    seen: dict = {}
    for _, row in df.iterrows():
        aid = _opt(row.get("Alert ID"))
        if not aid:
            continue
        source = _opt(row.get("File")) or ""
        if aid not in seen or "OFAC SDN" in source.upper():
            seen[aid] = row

    alerts: List[Alert] = []
    for aid, row in seen.items():
        try:
            score = float(str(row.get("List Screening Score", "0")).strip())
        except (ValueError, TypeError):
            score = 0.0

        entity_name = _opt(row.get("Entity Name")) or ""
        best_match = _opt(row.get("Best Match")) or ""
        aliases = [best_match] if best_match and best_match.upper() != entity_name.upper() else []

        ssn_raw = _opt(row.get("SSN"))
        ssn_confirmed = ssn_raw is not None and ssn_raw != ""

        alerts.append(Alert(
            alert_id=aid,
            account_id=_extract_customer_token(_opt(row.get("Account ID"))),
            customer_name=str(row.get("Name", "")).strip(),
            sdn_name=entity_name,
            match_score=score,
            customer_dob=_bridger_dob(_opt(row.get("DOB"))),
            sdn_dob=_bridger_dob(_opt(row.get("ERF_DOB"))),
            customer_ssn_confirmed=ssn_confirmed,
            sdn_aliases=aliases,
            sdn_program=_opt(row.get("File")),
        ))

    log.info("Loaded %d unique alerts from Bridger CSV (%d raw rows)", len(alerts), len(df))
    return alerts
