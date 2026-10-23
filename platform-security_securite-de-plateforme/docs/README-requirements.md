# Platform Security Requirements Registry (CSV)

Structured requirement items extracted from the English source text in [Guideline for Secure Application Development Annex A: Secure Containers and Microservices](../README.md) (`en/*.md`). Use for compliance mapping, control traceability, and implementation tracking.

> **Disclaimer:** These materials are provided for technical alignment and do not constitute statutory legal advice. See the [repository disclaimer](../../../README.md#disclaimer).

## Files

| File | Description |
| --- | --- |
| [platform-security-requirements.csv](./platform-security-requirements.csv) | Full registry — **170** items |
| [platform-security-requirements-actionable.csv](./platform-security-requirements-actionable.csv) | **Actionable** subset only — **125** items (threats, considerations, best practices, numbered recommendations, principles, challenges) |

## Columns

| Column | Meaning |
| --- | --- |
| `requirement_id` | Stable ID, format `GC-PSA-####` |
| `chapter` | Source chapter number (2–5; Chapter 1 is introductory and not tabulated) |
| `section_id` | Section id, e.g. `4.4`, `5.8` |
| `section_title` | Section heading from the guideline |
| `domain` | Security domain code (e.g. `kubernetes`, `secrets`) |
| `domain_label` | Short English label for the domain |
| `item_type` | `threat`, `consideration`, `best_practice`, `numbered_recommendation`, `principle`, `challenge`, or `context` |
| `actionable` | `yes` — suitable for controls or backlog; `no` — background/context only |
| `item_name` | Short title from the source table or list |
| `description` | Full text from the source |
| `source_file` | Path under `en/` |

## Regenerate

Clone the upstream guideline (this catalog does not vendor `en/`):

```bash
git clone https://github.com/canada-ca/platform-security_securite-de-plateforme /tmp/platform-security_securite-de-plateforme
cd platform-security_securite-de-plateforme   # this dataset directory in gc-compliance-catalog
python3 scripts/extract_requirements_csv.py --source /tmp/platform-security_securite-de-plateforme
```

(`--source` defaults to the dataset package root; use it when `en/` lives in a separate clone.)

Output reflects the upstream `en/` markdown at the time you run the script. Re-run after guideline updates and commit the refreshed CSVs.
