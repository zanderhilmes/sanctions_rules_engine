"""
Shared utilities: date parsing (for DOB/age rules) and zip→state derivation.
"""
from __future__ import annotations

import re
from datetime import date
from typing import Dict, Optional

_MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
    "january": 1, "february": 2, "march": 3, "april": 4,
    "june": 6, "july": 7, "august": 8, "september": 9,
    "october": 10, "november": 11, "december": 12,
}

# Flag returned alongside a parsed date to signal year-only precision
_YEAR_ONLY_DAY = 1
_YEAR_ONLY_MONTH = 7  # Mid-year sentinel


def parse_date(s: Optional[str]) -> Optional[date]:
    """
    Parse a date string in any of the common formats found in sanctions data.

    Returns a date object, or None if unparseable.
    Year-only strings (e.g. "1960") return July 1 of that year as a sentinel
    — callers should use is_year_only() to detect this case and compare
    years only rather than full dates.
    """
    if not s:
        return None
    s = s.strip()

    # YYYY-MM-DD
    m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})$", s)
    if m:
        try:
            return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            pass

    # DD/MM/YYYY (guide format) or MM/DD/YYYY
    m = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})$", s)
    if m:
        try:  # Try DD/MM/YYYY first (guide uses this format)
            return date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
        except ValueError:
            pass
        try:  # Fall back to MM/DD/YYYY
            return date(int(m.group(3)), int(m.group(1)), int(m.group(2)))
        except ValueError:
            pass

    # DD MMM YYYY  e.g. "15 Jan 1960" (OFAC Remarks format)
    m = re.match(r"^(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})$", s)
    if m:
        month = _MONTH_MAP.get(m.group(2).lower())
        if month:
            try:
                return date(int(m.group(3)), month, int(m.group(1)))
            except ValueError:
                pass

    # MMM DD[,] YYYY  e.g. "Jan 15, 1960"
    m = re.match(r"^([A-Za-z]+)\s+(\d{1,2}),?\s+(\d{4})$", s)
    if m:
        month = _MONTH_MAP.get(m.group(1).lower())
        if month:
            try:
                return date(int(m.group(3)), month, int(m.group(2)))
            except ValueError:
                pass

    # YYYY only — return mid-year sentinel
    m = re.match(r"^(\d{4})$", s)
    if m:
        year = int(m.group(1))
        if 1900 <= year <= 2020:
            return date(year, _YEAR_ONLY_MONTH, _YEAR_ONLY_DAY)

    return None


def is_year_only(d: date) -> bool:
    """True if this date was produced from a year-only string (sentinel)."""
    return d.month == _YEAR_ONLY_MONTH and d.day == _YEAR_ONLY_DAY


# ---------------------------------------------------------------------------
# Zip → state derivation (used by geography rule when TLOxp/Notary unavailable)
# ---------------------------------------------------------------------------

_ZIP_PREFIX_STATE: Dict[str, str] = {
    "0": "NE",  "1": "NY",  "2": "DC",  "3": "FL",  "4": "KY",
    "5": "MN",  "6": "IL",  "7": "TX",  "8": "CO",  "9": "CA",
}
_ZIP3_STATE: Dict[str, str] = {
    "100": "NY", "101": "NY", "102": "NY", "103": "NY", "104": "NY",
    "105": "NY", "106": "NY", "107": "NY", "108": "NY", "109": "NY",
    "110": "NY", "111": "NY", "112": "NY", "113": "NY", "114": "NY",
    "115": "NY", "116": "NY", "117": "NY", "118": "NY", "119": "NY",
    "200": "DC", "201": "VA", "202": "DC", "203": "DC", "204": "DC",
    "205": "DC", "206": "DC", "207": "MD", "208": "MD", "209": "MD",
    "210": "MD", "211": "MD", "212": "MD",
    "300": "GA", "301": "GA", "302": "GA", "303": "GA",
    "330": "FL", "331": "FL", "332": "FL", "333": "FL", "334": "FL",
    "600": "IL", "601": "IL", "602": "IL", "603": "IL", "604": "IL",
    "606": "IL",
    "770": "TX", "771": "TX", "772": "TX", "773": "TX", "774": "TX",
    "900": "CA", "901": "CA", "902": "CA", "903": "CA", "904": "CA",
    "905": "CA", "906": "CA", "907": "CA", "908": "CA", "910": "CA",
    "911": "CA", "912": "CA", "913": "CA", "914": "CA", "915": "CA",
    "916": "CA", "917": "CA", "918": "CA", "919": "CA", "920": "CA",
    "921": "CA", "922": "CA", "923": "CA", "924": "CA", "925": "CA",
    "980": "WA", "981": "WA", "982": "WA", "983": "WA", "984": "WA",
    "850": "AZ", "851": "AZ", "852": "AZ", "853": "AZ", "854": "AZ",
    "191": "PA", "192": "PA", "193": "PA", "194": "PA", "195": "PA",
    "196": "PA",
    "021": "MA", "022": "MA", "023": "MA", "024": "MA", "025": "MA",
    "026": "MA", "027": "MA",
}


def zip_to_state(zip_code: Optional[str]) -> Optional[str]:
    """Derive a US state abbreviation from a zip code prefix."""
    if not zip_code:
        return None
    z = str(zip_code).strip().zfill(5)[:5]
    return _ZIP3_STATE.get(z[:3]) or _ZIP3_STATE.get(z[:2]) or _ZIP_PREFIX_STATE.get(z[0])
