"""
Sanctions Rules Engine — CLI entrypoint.

Usage:
    python main.py --generate-sample
    python main.py --input data/sample_alerts.csv
    python main.py --input file1.csv file2.csv file3.csv
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Load .env if present (no-op if file doesn't exist or dotenv not installed)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_generate(args: argparse.Namespace) -> None:
    from sanctions.generator.alert_generator import generate_alerts, write_csv
    n = args.count
    output = args.output or "data/sample_alerts.csv"
    alerts = generate_alerts(n=n)
    write_csv(alerts, path=output)


def cmd_run(args: argparse.Namespace) -> None:
    from sanctions.config import load_config
    from sanctions.pipeline.processor import SanctionsPipeline, load_alerts

    config = load_config(args.config)
    pipeline = SanctionsPipeline(config)

    all_alerts = []
    seen_ids: set = set()
    for input_path in args.input:
        if not Path(input_path).exists():
            print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
            sys.exit(1)
        batch = load_alerts(input_path)
        fmt = "JSON-lines" if input_path.endswith(".json") else "CSV"
        # Deduplicate across files by alert_id
        new = [a for a in batch if a.alert_id not in seen_ids]
        seen_ids.update(a.alert_id for a in new)
        all_alerts.extend(new)
        print(f"Loaded {len(new)} alerts from {Path(input_path).name} ({fmt})"
              + (f" [{len(batch)-len(new)} duplicates skipped]" if len(batch) != len(new) else ""))

    print(f"Total: {len(all_alerts)} unique alerts across {len(args.input)} file(s)")
    records = pipeline.run(all_alerts)
    pipeline.write_output(records)
    pipeline.print_summary(records)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sanctions Rules Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 50 sample alerts (for standalone testing)
  python main.py --generate-sample

  # Run on a single Bridger CSV
  python main.py --input data/sample_alerts.csv

  # Run on multiple Bridger CSVs in one pass (single Snowflake connection)
  python main.py --input file1.csv file2.csv file3.csv
        """,
    )
    parser.add_argument("--generate-sample", action="store_true",
                        help="Generate a sample alerts CSV and exit")
    parser.add_argument("--count", type=int, default=50, metavar="N",
                        help="Number of sample alerts to generate (default: 50)")
    parser.add_argument("--output", type=str, default=None, metavar="PATH",
                        help="Output path for generated alerts (default: data/sample_alerts.csv)")
    parser.add_argument("--input", type=str, nargs="+", metavar="PATH",
                        help="One or more alert CSV / JSON files to process")
    parser.add_argument("--config", type=str, default="config.yaml", metavar="PATH",
                        help="Path to config.yaml (default: config.yaml)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")

    args = parser.parse_args()
    _setup_logging(args.verbose)

    if args.generate_sample:
        cmd_generate(args)
    elif args.input:
        cmd_run(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
