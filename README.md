# Sanctions Rules Engine

A Python rules engine for auto-clearing and escalating OFAC sanctions screening alerts from Bridger. It applies a deterministic rule hierarchy first, then falls back to an LLM (Claude) for ambiguous cases.

## Overview

Bridger produces a screening alert for every customer name that fuzzy-matches the OFAC SDN list. Most alerts are false positives. This engine processes those alerts and automatically clears the obvious false positives, escalates true matches, and sends borderline cases to Claude for a reasoned determination.

**Decision outcomes:**

| Decision | Meaning |
|---|---|
| `AUTO_CLEAR` | Deterministically cleared by rules — no manual review needed |
| `ESCALATE` | High confidence of a true match — send to a human analyst |
| `PENDING` | Inconclusive — sent to Claude LLM for a reasoned determination |

---

## Architecture

```
Bridger CSV
    │
    ▼
SanctionsPipeline
    │
    ├── SnowflakeEnricher   (customer DOB, IDV status, account creation date, address state)
    ├── OFACEnricher        (SDN DOB, date-added, place-of-birth country from sdn_advanced.xml)
    └── TLOxpEnricher       (customer DOB + state from TLOxp — stub, no API key yet)
    │
    ├── RuleRegistry        (weighted-vote engine, runs all rules)
    │
    └── ClaudeClient        (LLM review for PENDING cases only)
    │
    ▼
audit_trail_<timestamp>.csv / audit_trail_<timestamp>.json
```

### Key files

| Path | Purpose |
|---|---|
| `main.py` | CLI entrypoint |
| `config.yaml` | All configuration (models, thresholds, credentials) |
| `sanctions/models.py` | Pydantic data models: `Alert`, `RuleFlag`, `Disposition`, `AuditRecord` |
| `sanctions/config.py` | Typed config loader with env-var interpolation |
| `sanctions/pipeline/processor.py` | `SanctionsPipeline` orchestrator |
| `sanctions/rules/registry.py` | Weighted-vote accumulator + resolution logic |
| `sanctions/enrichment/` | Snowflake, OFAC XML, TLOxp enrichers |
| `sanctions/rules/` | Individual rule implementations |
| `sanctions/llm/` | Claude API client + prompt builder |

---

## Rules

All rules run on every alert for audit completeness. The registry applies this resolution order after all rules have fired:

1. **HARD CLEAR** — any CLEAR vote with weight ≥ 0.90 → `AUTO_CLEAR` (overrides everything, including hard escalation)
2. **CONTESTED** — hard escalate present AND a strong-but-not-hard CLEAR vote (weight ≥ 0.70) → `PENDING` → LLM adjudicates the conflict
3. **HARD ESCALATE** — any ESCALATE vote with weight ≥ 0.90, no competing clear → `ESCALATE`
4. **Weighted clear score** ≥ threshold (default 0.65) → `AUTO_CLEAR`
5. Otherwise → `PENDING` (sent to LLM)

Soft ESCALATE votes (weight < 0.90) subtract from the cumulative clear score rather than setting the hard-escalate flag, allowing risk signals to reduce auto-clear confidence without forcing mandatory escalation.

| Rule | Priority | Direction | Weight | Guide ref | Trigger condition |
|---|---|---|---|---|---|
| `prior_sanctions_denylist` | 3 | ESCALATE | 0.95 | — | Customer was previously denylisted for sanctions |
| `name_components` | 5 | CLEAR / ESCALATE | 0.85 / 0.80 | F+ 1A | Token-set comparison (3-case table) |
| `alias_match` | 6 | ESCALATE | 0.95 | — | Customer name matches an SDN alias |
| `low_score` | 10 | CLEAR | 0.60 | — | Match score < 30 |
| `dob_mismatch` | 15 | CLEAR | 0.90 / 0.75 | F+ 1B | Customer DOB ≠ SDN DOB; 0.90 for IDV-confirmed or low-score, 0.75 (contested) for high-score unverified |
| `age_improbability` | 16 | CLEAR | 0.90 / 0.50 | F+ 1D | SDN added before customer was born (hard) or customer was very young at time of listing (soft) |
| `missing_dob` | 17 | ESCALATE | 0.30 | — | No customer DOB on record; soft signal that reduces auto-clear confidence |
| `common_name` | 20 | CLEAR | 0.45 | — | Customer name is a high-frequency common name |
| `geography` | 30 | CLEAR | 0.35 | — | US customer (zip or state) vs foreign SDN country |

**Key hierarchy note:** A name token match (`name_components` ESCALATE 0.80) combined with a hard DOB mismatch (`dob_mismatch` CLEAR 0.90) results in AUTO_CLEAR — the hard clear overrides at step 1. When DOB data is unverified and the match score is high, `dob_mismatch` fires a contested clear (0.75), triggering step 2: PENDING → LLM. This implements the guide's instruction to evaluate DOB after name — a confirmed DOB mismatch clears even a strong name match.

**`alias_match` note:** Weight 0.95 (hard escalate) ensures that when a customer name matches an SDN alias, the case always routes to LLM or escalation. A hard DOB mismatch (0.90) still auto-clears via step 1. A contested DOB mismatch (0.75, high score + unverified) triggers step 2 → LLM.

---

## Enrichment

### Customer data (Snowflake)

Customer DOB is the most powerful signal — it enables the DOB mismatch hard-clear. The pipeline backfills from these sources in order of preference (first hit wins):

1. **`IDENTITY_DOB_HISTORY`** — primary source; the table that backs `CASH_W_DOB`. Returns a full `DOB DATE` column.
2. **`IDENTITY_IDV_ATTEMPTS`** — fallback; only present for customers who completed IDV. Also sets `customer_verified = True` when a successful attempt exists.
3. **`CUSTOMER_SUMMARY`** — last resort; year-only `BIRTH_YEAR` column.
4. **Account creation date proxy** — when no DOB is available, `AgeImprobabilityRule` derives the latest possible birth year from `CUSTOMER_CREATED_AT` minus the minimum signup age (18). Enables the age rule without populating `customer_dob`.

**IDV-confirmed address** (`customer_state`) is populated from `IDENTITY_IDV_ATTEMPTS` when `snowflake.address_state_col` is configured. This is required for the country mismatch rule (currently disabled — see below).

### SDN data (OFAC XML)

OFAC's `sdn_advanced.xml` is downloaded at startup and cached for 24 hours. It backfills:

| Field | Source in XML | Used by |
|---|---|---|
| `sdn_dob` | `Feature[@FeatureTypeID='8']` (Birthdate) | `dob_mismatch` rule |
| `sdn_date_added` | `SanctionsEntries/EntryEvent/Date` | `age_improbability` rule |
| `sdn_country` | `Feature[@FeatureTypeID='9']` (Place of Birth) | Audit trail only — **not used for rule-based clearing** |

`sdn_dob` and `sdn_date_added` are typically absent from Bridger CSV exports. The preferred long-term fix is to configure Bridger's `ERF_DOB` export field; until then, the OFAC XML enricher handles it automatically.

`sdn_country` is derived from Place of Birth and is visible in the audit trail for analyst context. It is intentionally not used for auto-clearing: place of birth is not equivalent to current residence, and an SDN may reside in a different country.

### Country mismatch rule (disabled)

`CountryMismatchRule` (`sanctions/rules/rule_country_mismatch.py`) is implemented but not registered. It would hard-clear (weight 0.95) when a customer has a confirmed US address AND the SDN's location is non-US. Two data sources are required before it can be enabled:

1. **Customer address** — configure `snowflake.address_state_col` to pull a US state from a verified IDV record
2. **SDN location** — a reliable non-POB source for the SDN's location (OFAC Place of Birth ≠ current residence)

To re-enable once both sources are available, uncomment the two lines in `sanctions/pipeline/processor.py`.

---

## Quickstart

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure credentials

```bash
cp .env.example .env
# Add ANTHROPIC_API_KEY (required for LLM review of PENDING cases)
```

### 3. Configure Snowflake (optional — rules run without it)

Edit `config.yaml`:

```yaml
snowflake:
  enabled: true
  account: "${SNOWFLAKE_ACCOUNT}"    # set in .env or environment
  user: "${SNOWFLAKE_USER}"
  warehouse: "ADHOC__MEDIUM"
  authenticator: "externalbrowser"   # or "https://login.block.xyz" for Okta SSO
```

### 4. Run

```bash
# Run on a Bridger CSV export
python main.py --input path/to/bridger_export.csv

# Run on multiple files in one pass (single Snowflake connection)
python main.py --input file1.csv file2.csv file3.csv

# Generate synthetic test data
python main.py --generate-sample
python main.py --input data/sample_alerts.csv

# Debug logging
python main.py --input path/to/bridger_export.csv -v
```

### 5. Review output

Results are written to timestamped files:
- `output/audit_trail_<timestamp>.csv` — one row per alert with decision, confidence, triggered rules, LLM rationale
- `output/audit_trail_<timestamp>.json` — same in JSON-lines format

---

## Configuration reference

```yaml
llm:
  model: "claude-haiku-4-5-20251001"       # Fast model for most LLM calls
  escalation_model: "claude-sonnet-4-6"    # Stronger model when match_score >= threshold
  strong_model_score_threshold: 70.0       # Score above which to use the stronger model
  max_tokens: 512

rules:
  auto_clear_confidence_threshold: 0.65    # Weighted clear score required to auto-clear
  escalate_hard_weight: 0.90               # ESCALATE weight threshold for hard-escalate
  clear_hard_weight: 0.90                  # CLEAR weight threshold for hard-clear
  low_score_clear_threshold: 30.0          # Match score below which low_score rule fires
  dob_mismatch_high_score_threshold: 80.0  # Score above which DOB mismatch uses contested weight (0.75)
  common_names_file: "data/common_names.txt"
  age_improbability_max_years: 5           # Customer age at sanctioning below which soft-clear fires
  min_signup_age: 18                       # Minimum age at account creation (DOB proxy)

snowflake:
  enabled: true
  dob_history_table: "APP_CASH.HEALTH.IDENTITY_DOB_HISTORY"
  customer_summary_table: "APP_CASH.APP.CUSTOMER_SUMMARY"
  account_table: "APP_CASH.APP.CASH_CUSTOMER_IDENTITY_W_AFTERPAY"
  account_id_col: "CUSTOMER_TOKEN"
  account_created_col: "CUSTOMER_CREATED_AT"
  address_state_col: ""        # e.g. "STATE" — column in IDV table with US state; blank = skip

ofac:
  enabled: true
  cache_path: "data/sdn_advanced.xml"
  max_age_hours: 24            # Re-download after this many hours; OFAC updates daily

tlo:
  enabled: false               # Enable once TLOXP_API_KEY + TLOXP_API_URL are provisioned
```

---

## Adding a custom rule

1. Create `sanctions/rules/rule_my_rule.py`:

```python
from sanctions.models import Alert, RuleFlag
from sanctions.rules.base_rule import BaseRule

class MyRule(BaseRule):
    name = "my_rule"
    weight = 0.50
    priority = 50   # Higher number = runs later

    def evaluate(self, alert: Alert) -> RuleFlag:
        if <condition>:
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="CLEAR",   # or "ESCALATE"
                weight=self.weight,
                detail="Reason for this decision",
            )
        return RuleFlag(rule_name=self.name, triggered=False, direction=None, weight=self.weight)
```

2. Register it in `sanctions/pipeline/processor.py`:

```python
from sanctions.rules.rule_my_rule import MyRule
# ...
self.registry.register(MyRule())
```

---

## TLOxp setup

TLOxp access requires an API key that has not yet been provisioned. Once available:

1. Set `TLOXP_API_KEY` and `TLOXP_API_URL` in `.env`
2. Fill in the two TODOs in `sanctions/enrichment/tlo_client.py`:
   - `_SEARCH_ENDPOINT` — the actual search path
   - `_parse_response()` — field names in the response JSON
3. Set `tlo.enabled: true` in `config.yaml`
