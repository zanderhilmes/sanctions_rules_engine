"""
Generates mock alert CSV with four realistic archetypes:

  1. obvious_fp      — very low score (<30), common name, domestic zip  → AUTO_CLEAR
  2. geo_mismatch    — moderate score, reordered name, domestic US zip  → CLEAR via name/geo
  3. borderline      — score 45–65, name closely matches, plausible geo → LLM needed
  4. high_risk       — score >=70, name closely matches, no zip         → ESCALATE / LLM

DOB columns (customer_dob, sdn_dob, sdn_date_added) are included in the CSV
so the DOB-mismatch and age-improbability rules can be exercised in the demo
even without real OFAC SDN files loaded.  In production these SDN fields come
from the enricher parsing the OFAC Remarks column.
"""
from __future__ import annotations

import csv
import random
import uuid
from pathlib import Path
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Archetype data pools
# ---------------------------------------------------------------------------

COMMON_NAMES = [
    "John Smith", "Jane Doe", "Michael Johnson", "Sarah Williams",
    "David Brown", "Jennifer Davis", "Robert Miller", "Linda Wilson",
    "James Moore", "Patricia Taylor",
]

SDN_COMMON_NAMES = [
    "JOHN SMITH", "JANE DOE", "MICHAEL JOHNSON", "SARAH WILLIAMS",
    "DAVID BROWN", "JENNIFER DAVIS",
]

US_ZIPS = [
    ("10001", "NY"), ("90210", "CA"), ("60601", "IL"),
    ("77001", "TX"), ("30301", "GA"), ("98101", "WA"),
    ("85001", "AZ"), ("19101", "PA"), ("33101", "FL"),
    ("02101", "MA"),
]

BORDERLINE_CUSTOMER_NAMES = [
    "Hassan Rashid", "Ali Khamenei", "Igor Petrov",
    "Mehmet Yildirim", "Chen Wei", "Omar Hussein",
]

BORDERLINE_SDN_NAMES = [
    "HASSAN AL RASHID", "ALI KHOMEINI", "IGOR PETROV",
    "MEHMET YILDIZ", "CHEN WEI ZHANG", "OMAR AL HUSAIN",
]

# Mock SDN DOBs in OFAC Remarks format (from the 1940s–1960s — clearly different
# from young US customers born in the 1980s–2000s)
_MOCK_SDN_DOBS = [
    "15 Jan 1948", "23 Mar 1952", "07 Aug 1943",
    "11 Nov 1961", "28 Jun 1957", "14 Sep 1950",
]


def _rand_dob(year_min: int, year_max: int) -> str:
    """Return a random YYYY-MM-DD DOB string."""
    y = random.randint(year_min, year_max)
    m = random.randint(1, 12)
    d = random.randint(1, 28)
    return f"{y}-{m:02d}-{d:02d}"


# ---------------------------------------------------------------------------
# Generators per archetype
# ---------------------------------------------------------------------------

def _obvious_fp() -> dict:
    """
    Low-score common-name alert.  Sub-variants exercise DOB and age rules:
      dob_mismatch      — customer DOB clearly differs from SDN DOB → F+ 1B
      age_improbability — SDN added before customer was born         → F+ 1D
      no_dob            — no DOB data available (score + name clears it)
    """
    name = random.choice(COMMON_NAMES)
    sdn = random.choice(SDN_COMMON_NAMES)
    zip_code, _ = random.choice(US_ZIPS)
    base = {
        "alert_id": str(uuid.uuid4())[:8],
        "customer_name": name,
        "sdn_name": sdn,
        "match_score": round(random.uniform(10.0, 28.0), 1),
        "zip_code": zip_code,
    }

    variant = random.choices(
        ["dob_mismatch", "age_improbability", "no_dob"],
        weights=[0.40, 0.30, 0.30],
        k=1,
    )[0]

    if variant == "dob_mismatch":
        customer_year = random.randint(1985, 2000)
        base["customer_dob"] = _rand_dob(customer_year, customer_year + 5)
        base["sdn_dob"] = random.choice(_MOCK_SDN_DOBS)  # 1940s–1960s
        base["sdn_date_added"] = None
    elif variant == "age_improbability":
        customer_year = random.randint(1992, 2001)
        base["customer_dob"] = _rand_dob(customer_year, customer_year)
        base["sdn_dob"] = None
        # SDN was added 1–8 years before customer was born
        added_year = customer_year - random.randint(1, 8)
        base["sdn_date_added"] = f"{added_year}-01-17"
    else:
        base["customer_dob"] = None
        base["sdn_dob"] = None
        base["sdn_date_added"] = None

    return base


def _geo_mismatch() -> dict:
    """Reordered name (same tokens) — clears via name_components token-set match... wait,
    reordered names ESCALATE by name_components.  This archetype is meant to be cleared by
    the geo rule when SDN country is foreign.  Without real SDN files, these remain PENDING
    and go to LLM.  DOBs not included — geo is the distinguishing signal."""
    first = random.choice(["Carlos", "Ahmed", "Yuki", "Fatima", "Ivan", "Wei"])
    last = random.choice(["Garcia", "Mohamed", "Tanaka", "Hassan", "Petrov", "Liu"])
    customer_name = f"{first} {last}"
    sdn_name = f"{last.upper()} {first.upper()}"
    zip_code, _ = random.choice(US_ZIPS)
    return {
        "alert_id": str(uuid.uuid4())[:8],
        "customer_name": customer_name,
        "sdn_name": sdn_name,
        "match_score": round(random.uniform(35.0, 60.0), 1),
        "zip_code": zip_code,
        "customer_dob": None,
        "sdn_dob": None,
        "sdn_date_added": None,
    }


def _borderline() -> dict:
    idx = random.randrange(len(BORDERLINE_CUSTOMER_NAMES))
    zip_code, _ = random.choice(US_ZIPS)
    return {
        "alert_id": str(uuid.uuid4())[:8],
        "customer_name": BORDERLINE_CUSTOMER_NAMES[idx],
        "sdn_name": BORDERLINE_SDN_NAMES[idx],
        "match_score": round(random.uniform(45.0, 65.0), 1),
        "zip_code": zip_code,
        "customer_dob": None,
        "sdn_dob": None,
        "sdn_date_added": None,
    }


def _high_risk() -> dict:
    idx = random.randrange(len(BORDERLINE_CUSTOMER_NAMES))
    return {
        "alert_id": str(uuid.uuid4())[:8],
        "customer_name": BORDERLINE_CUSTOMER_NAMES[idx],
        "sdn_name": BORDERLINE_SDN_NAMES[idx],
        "match_score": round(random.uniform(70.0, 95.0), 1),
        "zip_code": None,
        "customer_dob": None,
        "sdn_dob": None,
        "sdn_date_added": None,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

ARCHETYPE_WEIGHTS: List[Tuple[callable, float]] = [
    (_obvious_fp, 0.35),
    (_geo_mismatch, 0.30),
    (_borderline, 0.20),
    (_high_risk, 0.15),
]


def generate_alerts(n: int = 50, seed: int = 42) -> List[dict]:
    random.seed(seed)
    archetypes = [fn for fn, _ in ARCHETYPE_WEIGHTS]
    weights = [w for _, w in ARCHETYPE_WEIGHTS]
    return [random.choices(archetypes, weights=weights, k=1)[0]() for _ in range(n)]


def write_csv(alerts: List[dict], path: str = "data/sample_alerts.csv") -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "alert_id", "customer_name", "sdn_name", "match_score", "zip_code",
        "customer_dob", "sdn_dob", "sdn_date_added",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(alerts)
    print(f"[generator] Wrote {len(alerts)} alerts to {path}")


if __name__ == "__main__":
    alerts = generate_alerts(50)
    write_csv(alerts)
