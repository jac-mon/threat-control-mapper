# Threat-to-Control Mapper

A command-line tool that maps MITRE ATT&CK techniques to NIST 800-53 Rev 5 controls and identifies detection coverage gaps using user-supplied Sigma rules.

Built to bridge the gap between detection engineering and governance, risk, and compliance (GRC) — answering the question: *which compliance controls do my detections actually satisfy, and where are the holes?*

---

## The Problem This Solves

Security teams write detection rules. GRC teams manage control frameworks. These two functions rarely talk to each other in a structured, repeatable way.

This tool operationalizes that relationship:
- Given a set of Sigma detection rules, which ATT&CK techniques are covered?
- Which NIST 800-53 controls does that coverage support?
- Where are the detection gaps, and which controls are left unsupported as a result?

The output can inform POA&M entries, continuous monitoring reporting, and detection engineering priorities simultaneously.

---

## How It Works

```
Sigma Rules (.yaml)
        +
ATT&CK → 800-53 Mapping (.yaml)
        ↓
detection_governance.py (CLI)
        ↓
Console Summary + Gap Report (.md)
```

1. Drop your Sigma rules into `sigma_rules/`
2. Run `detection_governance.py` against a single technique or all techniques
3. Review the gap report to identify which 800-53 controls lack detection support

---

## Project Structure

```
threat-control-mapper/
├── mappings/
│   └── attck_to_80053.yaml      # ATT&CK technique → NIST 800-53 control mappings
├── sigma_rules/
│   └── *.yaml                   # User-supplied Sigma detection rules
├── scripts/
│   └── detection_governance.py  # CLI tool
├── reports/
│   └── gap_report.md            # Auto-generated output (see example below)
├── requirements.txt
└── README.md
```

---

## Setup

```bash
git clone https://github.com/[your-username]/threat-control-mapper.git
cd threat-control-mapper
pip install -r requirements.txt
```

---

## Usage

**Analyze a single technique:**
```bash
python scripts/detection_governance.py --technique T1059.001
```

**Analyze all techniques in the mapping file:**
```bash
python scripts/detection_governance.py --all
```

**Write a markdown gap report:**
```bash
python scripts/detection_governance.py --all --output reports/gap_report.md
```

---

## Example Output

```
============================================================
  THREAT-TO-CONTROL MAPPER — RESULTS
============================================================

[✅ COVERED] T1059.001 — PowerShell
  Tactic:   Execution
  Controls: AU-2, AU-12, CM-6, CM-7, SI-4
  Rules:    PowerShell Encoded Command Execution

[❌ GAP] T1078 — Valid Accounts
  Tactic:   Defense Evasion, Persistence, Privilege Escalation, Initial Access
  Controls: AC-2, AC-3, AC-7, IA-2, IA-5, AU-2, SI-4
  Rules:    None — detection gap identified
```

The full markdown report includes an executive summary table, per-technique control breakdowns, and a prioritized recommendation checklist.

---

## Adding Your Own Sigma Rules

Drop any Sigma-compliant `.yaml` file into `sigma_rules/`. The tool reads the `tags` field to extract ATT&CK technique IDs:

```yaml
tags:
  - attack.execution
  - attack.t1059.001   # ← This is what the tool uses for mapping
```

As long as your rule follows the standard Sigma tag format, it will be picked up automatically.

---

## Expanding the Mapping File

`mappings/attck_to_80053.yaml` currently covers 10 high-priority techniques. To add more:

```yaml
- technique_id: T1055
  technique_name: Process Injection
  tactic: Defense Evasion, Privilege Escalation
  controls:
    - id: SI-4
      name: System Monitoring
      rationale: Monitors for anomalous process memory behavior
    - id: AU-12
      name: Audit Record Generation
      rationale: Captures process creation and access events
```

Mapping rationale should reference the specific control objective from NIST SP 800-53 Rev 5.

---

## Relevant Frameworks

- [MITRE ATT&CK v14](https://attack.mitre.org/)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma/wiki/Specification)

---

## Author

Jac-Mon | [LinkedIn](https://www.linkedin.com/in/jacquelinemontano/)
