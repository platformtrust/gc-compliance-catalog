#!/usr/bin/env python3
"""Extract guidance/requirement items from en/*.md into a CSV registry."""

import argparse
import csv
import re
import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
OUT = PACKAGE_ROOT / "docs" / "platform-security-requirements.csv"
OUT_ACTIONABLE = PACKAGE_ROOT / "docs" / "platform-security-requirements-actionable.csv"
UPSTREAM = "https://github.com/canada-ca/platform-security_securite-de-plateforme"

ACTIONABLE_TYPES = {
    "threat",
    "consideration",
    "best_practice",
    "numbered_recommendation",
    "principle",
    "challenge",
}

DOMAIN_BY_SECTION_PREFIX = [
    ("4.1", "host", "Host security"),
    ("4.2", "image_build", "Image builds"),
    ("4.3", "deployment", "Container deployment"),
    ("4.4", "kubernetes", "Kubernetes orchestration"),
    ("5.1", "platform", "Platform and multi-tenancy"),
    ("5.2", "runtime", "Container runtime"),
    ("5.3", "traffic", "Traffic security"),
    ("5.4", "secure_coding", "Secure coding"),
    ("5.5", "cloud_architecture", "Cloud architecture"),
    ("5.6", "image_security", "Container images"),
    ("5.7", "observability", "Observability"),
    ("5.8", "secrets", "Secrets management"),
    ("5.9", "cicd", "CI/CD"),
    ("5.10", "iac", "Infrastructure as code"),
    ("3", "threat_model", "Threat environment"),
    ("2.4", "container_security", "Container security"),
    ("2.6", "serverless", "Serverless / FaaS"),
    ("2", "context", "Context"),
]


def domain_for(section_id: str) -> tuple[str, str]:
    for prefix, code, label in DOMAIN_BY_SECTION_PREFIX:
        if section_id == prefix or section_id.startswith(prefix + "."):
            return code, label
    return "general", "General"

HTML_TAG = re.compile(r"<[^>]+>")
WS = re.compile(r"\s+")


def clean(text: str) -> str:
    text = HTML_TAG.sub(" ", text)
    text = text.replace("&nbsp;", " ")
    return WS.sub(" ", text).strip()


def strip_bold(title: str) -> str:
    return clean(re.sub(r"\*\*([^*]+)\*\*", r"\1", title))


def section_id_from_header(line: str) -> str | None:
    m = re.match(r"^#{1,3}\s+(.+)$", line.strip())
    if not m:
        return None
    raw = m.group(1).strip()
    num = re.match(r"^(\d+(?:\.\d+)*)", raw)
    return num.group(1) if num else None


def infer_item_type(section: str, col0_header: str) -> str:
    h = col0_header.lower()
    if "threat" in h:
        return "threat"
    if "principle" in h:
        return "principle"
    if "challenge" in h:
        return "challenge"
    if "benefit" in h or "upside" in h or "feature" in h and section.startswith("2."):
        return "context"
    if "best practice" in h or "recommendation" in section.lower():
        return "best_practice"
    if "consideration" in h:
        return "consideration"
    return "guidance"


def parse_file(path: Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    chapter = path.stem.split("_", 1)[0]  # e.g. 4_Implementation -> 4
    current_section = ""
    current_section_id = ""
    rows: list[dict] = []
    i = 0

    while i < len(lines):
        line = lines[i]

        if line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            title = line.lstrip("#").strip()
            sid = section_id_from_header(line) or ""
            if level <= 2:
                current_section = title
                current_section_id = sid
            elif level == 3:
                current_section = title
                current_section_id = sid or current_section_id

        m_num = re.match(r"^(\d+)\.\s+(.+)$", line.strip())
        if m_num and path.name.startswith("4_"):
            desc = clean(m_num.group(2))
            rows.append(
                {
                    "chapter": chapter,
                    "section_id": current_section_id,
                    "section_title": current_section,
                    "item_type": "numbered_recommendation",
                    "item_name": f"Recommendation {m_num.group(1)}",
                    "description": desc,
                    "source_file": f"en/{path.name}",
                }
            )

        if line.strip().startswith("|") and i + 1 < len(lines):
            if re.match(r"^\|\s*[-:]+", lines[i + 1].strip()):
                header_cells = [c.strip() for c in line.strip().strip("|").split("|")]
                i += 2
                col0_name = header_cells[0] if header_cells else "Item"
                item_type_default = infer_item_type(current_section_id, col0_name)
                while i < len(lines) and lines[i].strip().startswith("|"):
                    cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                    if len(cells) >= 2:
                        name = strip_bold(cells[0])
                        desc = clean(cells[1])
                        if name and name.lower() not in ("consideration", "description", "---"):
                            rows.append(
                                {
                                    "chapter": chapter,
                                    "section_id": current_section_id,
                                    "section_title": current_section,
                                    "item_type": item_type_default,
                                    "item_name": name,
                                    "description": desc,
                                    "source_file": f"en/{path.name}",
                                }
                            )
                    i += 1
                continue

        if path.name.startswith("5_") and re.match(r"^(\d+)\.\s+", line.strip()):
            if "Securing Container Runtime" in current_section or current_section_id == "5.2":
                desc = clean(re.sub(r"^\d+\.\s+", "", line.strip()))
                rows.append(
                    {
                        "chapter": chapter,
                        "section_id": current_section_id,
                        "section_title": current_section,
                        "item_type": "numbered_recommendation",
                        "item_name": desc[:80] + ("..." if len(desc) > 80 else ""),
                        "description": desc,
                        "source_file": f"en/{path.name}",
                    }
                )

        i += 1

    return rows


def add_manual_items() -> list[dict]:
    """Narrative requirements not captured in tables."""
    return [
        {
            "chapter": "5",
            "section_id": "5.1",
            "section_title": "5.1 Securing Platform — Multi-Tenancy",
            "item_type": "best_practice",
            "item_name": "Single application per cluster (strongest isolation)",
            "description": "The most secure multi-tenancy approach is deploying only one application per Kubernetes cluster; shared clusters trade efficiency for isolation strength.",
            "source_file": "en/5_Microservice_Security.md",
        },
        {
            "chapter": "4",
            "section_id": "4.4",
            "section_title": "4.4 Orchestration - Kubernetes",
            "item_type": "best_practice",
            "item_name": "Prefer managed Kubernetes service",
            "description": "Where possible, use a managed Kubernetes service from a cloud provider for additional security features, managed control plane, and timely security patches.",
            "source_file": "en/4_Implementation-Recommendations.md",
        },
        {
            "chapter": "4",
            "section_id": "4.4",
            "section_title": "4.4 Orchestration - Kubernetes",
            "item_type": "best_practice",
            "item_name": "Self-managed cluster hardening",
            "description": "When managing your own cluster, follow CIS Kubernetes Benchmark; verify with kube-bench or kubesec.io.",
            "source_file": "en/4_Implementation-Recommendations.md",
        },
        {
            "chapter": "2",
            "section_id": "2.2",
            "section_title": "2.2 Infrastructure",
            "item_type": "best_practice",
            "item_name": "Harden container hosts",
            "description": "Harden hosts running container engines, Kubernetes nodes and pods, and serverless functions per GC security best practices; apply shared responsibility for managed services.",
            "source_file": "en/2_Context.md",
        },
        {
            "chapter": "2",
            "section_id": "2.6",
            "section_title": "2.6 Functions as a Service — Runtime monitoring",
            "item_type": "best_practice",
            "item_name": "FaaS runtime monitoring",
            "description": "Regardless of deployment method, monitor for abnormal behavior, remediate threats, support forensics, enforce runtime policies, and scan for vulnerabilities and dependencies.",
            "source_file": "en/2_Context.md",
        },
    ]


def resolve_en_dir(source: Path) -> Path:
    en_dir = source / "en"
    if en_dir.is_dir():
        return en_dir
    print(
        f"Missing {en_dir}. Clone {UPSTREAM} and pass --source /path/to/platform-security_securite-de-plateforme",
        file=sys.stderr,
    )
    raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build platform-security requirement CSVs from en/*.md")
    parser.add_argument(
        "--source",
        type=Path,
        default=PACKAGE_ROOT,
        help="Root of upstream platform-security_securite-de-plateforme clone (must contain en/)",
    )
    args = parser.parse_args()
    en_dir = resolve_en_dir(args.source.resolve())

    all_rows: list[dict] = []
    for md in sorted(en_dir.glob("*.md")):
        all_rows.extend(parse_file(md))
    all_rows.extend(add_manual_items())

    seen: set[tuple[str, str, str]] = set()
    unique: list[dict] = []
    for r in all_rows:
        key = (r["section_id"], r["item_name"], r["description"][:120])
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "requirement_id",
        "chapter",
        "section_id",
        "section_title",
        "domain",
        "domain_label",
        "item_type",
        "actionable",
        "item_name",
        "description",
        "source_file",
    ]
    enriched: list[dict] = []
    for idx, r in enumerate(unique, start=1):
        code, label = domain_for(r["section_id"])
        r = {
            **r,
            "requirement_id": f"GC-PSA-{idx:04d}",
            "domain": code,
            "domain_label": label,
            "actionable": "yes" if r["item_type"] in ACTIONABLE_TYPES else "no",
        }
        enriched.append(r)

    with OUT.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(enriched)

    actionable_rows = [r for r in enriched if r["actionable"] == "yes"]
    with OUT_ACTIONABLE.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(actionable_rows)

    print(f"Wrote {len(enriched)} items to {OUT}")
    print(f"Wrote {len(actionable_rows)} actionable items to {OUT_ACTIONABLE}")


if __name__ == "__main__":
    main()
