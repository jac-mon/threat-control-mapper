#!/usr/bin/env python3
"""
threat-control-mapper
---------------------
Maps MITRE ATT&CK techniques to NIST 800-53 controls and checks
whether user-supplied Sigma rules provide detection coverage.

Usage:
  python detection_governance.py --technique T1059.001
  python detection_governance.py --technique T1059.001 --output reports/gap_report.md
  python detection_governance.py --all
  python detection_governance.py --all --output reports/gap_report.md
"""

import argparse
import os
import sys
import yaml
from datetime import datetime


# ── Path configuration ────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
MAPPINGS_DIR = os.path.join(BASE_DIR, "..", "mappings")
SIGMA_DIR    = os.path.join(BASE_DIR, "..", "sigma_rules")
REPORTS_DIR  = os.path.join(BASE_DIR, "..", "reports")

MAPPING_FILE = os.path.join(MAPPINGS_DIR, "attck_to_80053.yaml")


# ── Loaders ───────────────────────────────────────────────────────────────────
def load_mappings():
    """Load ATT&CK to 800-53 mapping file."""
    if not os.path.exists(MAPPING_FILE):
        print(f"[ERROR] Mapping file not found: {MAPPING_FILE}")
        sys.exit(1)
    with open(MAPPING_FILE, "r") as f:
        data = yaml.safe_load(f)
    return data.get("mappings", [])


def load_sigma_rules():
    """
    Load all Sigma rules from sigma_rules/ directory.
    Returns a dict of {technique_id: [rule_title, ...]}
    """
    coverage = {}
    if not os.path.exists(SIGMA_DIR):
        return coverage

    for filename in os.listdir(SIGMA_DIR):
        if not filename.endswith(".yaml") and not filename.endswith(".yml"):
            continue
        filepath = os.path.join(SIGMA_DIR, filename)
        with open(filepath, "r") as f:
            rule = yaml.safe_load(f)

        tags = rule.get("tags", [])
        title = rule.get("title", filename)

        for tag in tags:
            # Sigma tags format: attack.tXXXX or attack.tXXXX.XXX
            if tag.startswith("attack.t"):
                technique_id = tag.replace("attack.", "").upper()
                if technique_id not in coverage:
                    coverage[technique_id] = []
                coverage[technique_id].append(title)

    return coverage


# ── Core logic ────────────────────────────────────────────────────────────────
def analyze_technique(technique_entry, sigma_coverage):
    """
    For a single technique mapping entry, determine:
    - Which 800-53 controls apply
    - Whether Sigma coverage exists
    - Which controls lack detection support
    """
    tid  = technique_entry["technique_id"]
    name = technique_entry["technique_name"]
    tactic = technique_entry["tactic"]
    controls = technique_entry["controls"]

    matched_rules = sigma_coverage.get(tid, [])
    has_coverage  = len(matched_rules) > 0

    # Controls that rely on active monitoring/detection (vs policy/config)
    detection_controls = {"AU-2", "AU-12", "SI-4"}

    gap_controls = []
    if not has_coverage:
        gap_controls = [
            c for c in controls
            if c["id"] in detection_controls
        ]

    return {
        "technique_id":   tid,
        "technique_name": name,
        "tactic":         tactic,
        "controls":       controls,
        "sigma_rules":    matched_rules,
        "has_coverage":   has_coverage,
        "gap_controls":   gap_controls,
    }


# ── Report generation ─────────────────────────────────────────────────────────
def build_report(results):
    """Build a markdown gap report from analysis results."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total     = len(results)
    covered   = sum(1 for r in results if r["has_coverage"])
    uncovered = total - covered

    lines = []
    lines.append("# Threat-to-Control Gap Report")
    lines.append(f"\n**Generated:** {now}")
    lines.append(f"**Framework:** NIST SP 800-53 Rev 5")
    lines.append(f"**Detection Source:** User-supplied Sigma Rules\n")
    lines.append("---\n")

    # Executive summary
    lines.append("## Summary\n")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Techniques Analyzed | {total} |")
    lines.append(f"| Techniques with Sigma Coverage | {covered} |")
    lines.append(f"| Techniques with NO Coverage (Gap) | {uncovered} |")
    lines.append(f"| Coverage Rate | {round((covered/total)*100, 1) if total else 0}% |\n")

    # Covered techniques
    lines.append("---\n")
    lines.append("## Covered Techniques\n")
    covered_results = [r for r in results if r["has_coverage"]]
    if covered_results:
        for r in covered_results:
            lines.append(f"### {r['technique_id']} — {r['technique_name']}")
            lines.append(f"**Tactic:** {r['tactic']}\n")
            lines.append(f"**Sigma Rules Detected:**")
            for rule in r["sigma_rules"]:
                lines.append(f"- {rule}")
            lines.append(f"\n**NIST 800-53 Controls:**")
            for c in r["controls"]:
                lines.append(f"- **{c['id']} — {c['name']}**: {c['rationale']}")
            lines.append("")
    else:
        lines.append("_No techniques with Sigma coverage found._\n")

    # Gap techniques
    lines.append("---\n")
    lines.append("## Gap Techniques (No Sigma Coverage)\n")
    gap_results = [r for r in results if not r["has_coverage"]]
    if gap_results:
        for r in gap_results:
            lines.append(f"### ⚠️ {r['technique_id']} — {r['technique_name']}")
            lines.append(f"**Tactic:** {r['tactic']}\n")
            lines.append(f"**NIST 800-53 Controls Mapped (Undetected):**")
            for c in r["controls"]:
                lines.append(f"- **{c['id']} — {c['name']}**: {c['rationale']}")
            if r["gap_controls"]:
                lines.append(f"\n**Detection-Specific Controls at Risk:**")
                for c in r["gap_controls"]:
                    lines.append(f"- ❌ **{c['id']} — {c['name']}** — No Sigma rule provides coverage")
            lines.append("")
    else:
        lines.append("_No gaps detected. All techniques have Sigma coverage._\n")

    lines.append("---\n")
    lines.append("## Recommendations\n")
    if gap_results:
        lines.append("The following Sigma rules should be developed to close detection gaps:\n")
        for r in gap_results:
            lines.append(f"- [ ] Write Sigma rule for **{r['technique_id']} — {r['technique_name']}**")
    else:
        lines.append("- Detection coverage is complete for all analyzed techniques.")
        lines.append("- Expand the mapping file to include additional ATT&CK techniques.")

    return "\n".join(lines)


# ── Output ────────────────────────────────────────────────────────────────────
def print_console_summary(results):
    """Print a quick summary to the terminal."""
    print("\n" + "="*60)
    print("  THREAT-TO-CONTROL MAPPER — RESULTS")
    print("="*60)
    for r in results:
        status = "✅ COVERED" if r["has_coverage"] else "❌ GAP"
        print(f"\n[{status}] {r['technique_id']} — {r['technique_name']}")
        print(f"  Tactic:   {r['tactic']}")
        print(f"  Controls: {', '.join(c['id'] for c in r['controls'])}")
        if r["has_coverage"]:
            print(f"  Rules:    {', '.join(r['sigma_rules'])}")
        else:
            print(f"  Rules:    None — detection gap identified")
    print("\n" + "="*60)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Map ATT&CK techniques to NIST 800-53 controls and identify Sigma coverage gaps."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--technique", "-t",
        type=str,
        help="ATT&CK technique ID to analyze (e.g. T1059 or T1059.001)"
    )
    group.add_argument(
        "--all", "-a",
        action="store_true",
        help="Analyze all techniques in the mapping file"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Optional: path to write markdown gap report (e.g. reports/gap_report.md)"
    )

    args = parser.parse_args()

    # Load data
    mappings       = load_mappings()
    sigma_coverage = load_sigma_rules()

    # Filter techniques
    if args.all:
        selected = mappings
    else:
        tid = args.technique.upper()
        selected = [m for m in mappings if m["technique_id"].upper() == tid]
        if not selected:
            print(f"[ERROR] Technique '{args.technique}' not found in mapping file.")
            print(f"  Available: {', '.join(m['technique_id'] for m in mappings)}")
            sys.exit(1)

    # Analyze
    results = [analyze_technique(entry, sigma_coverage) for entry in selected]

    # Output
    print_console_summary(results)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        report = build_report(results)
        with open(args.output, "w") as f:
            f.write(report)
        print(f"\n[+] Report written to: {args.output}\n")


if __name__ == "__main__":
    main()
