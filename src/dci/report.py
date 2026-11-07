"""Report renderers. All snippets were redacted at extraction time."""
from __future__ import annotations

import json
from dataclasses import asdict

from .models import Confidence, Finding, Report, Severity

MARKER = "<!-- dci-report -->"
_AI_LABEL = {"likely_breaks": "Likely breaks", "likely_safe": "Likely safe", "unclear": "Unclear"}
MAX_COMMENT = 60_000


def _verdict(r: Report) -> str:
    b = r.blocking()
    if b:
        return f"FAIL ({len(b)} blocking)"
    if any(f.severity in (Severity.ERROR, Severity.WARNING) for f in r.findings):
        return "WARN"
    return "PASS"


def _counts(r: Report) -> str:
    c = {s: sum(1 for f in r.findings if f.severity == s) for s in Severity}
    return f"{c[Severity.ERROR]} error, {c[Severity.WARNING]} warning, {c[Severity.INFO]} info"


def _loc(f: Finding) -> str:
    return f"`{f.file}:{f.line}`" if f.file else ""


def _evidence_line(e) -> str:
    where = e.tree if e.tree != "head" else "this repo"
    snippet = e.snippet.replace("`", "'")
    note = f" ({e.note})" if e.note else ""
    t = " [test]" if e.is_test else ""
    return f"- `{e.file}:{e.line}`{t} [{where}; {e.via}; {e.confidence.value}]{note} `{snippet}`"


def to_markdown(r: Report, for_comment: bool = False) -> str:
    out: list[str] = []
    if for_comment:
        out.append(MARKER)
    out.append(f"## DCI database change check: {_verdict(r)}")
    out.append(f"{_counts(r)} · {len(r.changes)} schema change(s) in {len(r.coverage.migration_files)} migration file(s) · DCI {r.version}")
    out.append("")
    if not r.changes and not r.issues:
        out.append("No schema-changing operations were found in the analysed migrations.")
    order = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2}
    conf = {Confidence.CONFIRMED: 0, Confidence.POSSIBLE: 1, Confidence.UNKNOWN: 2}
    sorted_findings = sorted(r.findings, key=lambda f: (order[f.severity], conf[f.confidence], f.file, f.line, f.rule_id))

    confirmed = [f for f in sorted_findings if f.confidence == Confidence.CONFIRMED]
    advisory = [f for f in sorted_findings if f.confidence != Confidence.CONFIRMED]

    def _render_finding(f: Finding, compact: bool = False) -> list[str]:
        f_lines = []
        tag = f"{f.severity.value.upper()} · {f.confidence.value.upper()}"
        f_lines.append(f"### [{f.rule_id}] {f.title} — {tag}")
        what = f"{f.change.describe()}" if f.change else ""
        loc = _loc(f)
        if loc or what:
            f_lines.append(f"{loc} {what}".strip())
            f_lines.append("")
        f_lines.append(f.message)
        if f.evidence:
            f_lines.append("")
            f_lines.append(f"**Evidence ({len(f.evidence)} of {f.total_evidence} shown):**")
            f_lines.extend(_evidence_line(e) for e in f.evidence)
        if f.recommendation:
            f_lines.append("")
            if compact:
                f_lines.append("<details><summary><b>🛠️ Suggested safe sequence (expand & contract)</b></summary>\n")
                f_lines.extend(f"{i}. {s}" for i, s in enumerate(f.recommendation, 1))
                f_lines.append("\n</details>")
            else:
                f_lines.append("Suggested safe sequence:")
                f_lines.extend(f"{i}. {s}" for i, s in enumerate(f.recommendation, 1))
        if f.ai:
            f_lines.append("")
            f_lines.append(f"**AI-assisted analysis** (advisory, does not change the result; model `{f.ai.model}`): "
                           f"**{_AI_LABEL.get(f.ai.verdict, f.ai.verdict)}**. {f.ai.summary}")
            f_lines.extend(f"- cited `{c['file']}:{c['line']}`: `{c['quote']}`" for c in f.ai.citations)
            if f.ai.suggested_fix:
                f_lines.append(f"AI-suggested fix: {f.ai.suggested_fix}")
        f_lines.append("")
        return f_lines

    if for_comment and advisory and confirmed:
        for f in confirmed:
            out.extend(_render_finding(f, compact=True))
        out.append(f"<details><summary><b>⚠️ Advisory findings ({len(advisory)} non-blocking: {sum(1 for f in advisory if f.severity == Severity.WARNING)} warning, {sum(1 for f in advisory if f.severity == Severity.INFO)} info)</b></summary>\n")
        for f in advisory:
            out.extend(_render_finding(f, compact=True))
        out.append("</details>\n")
    else:
        for f in sorted_findings:
            out.extend(_render_finding(f, compact=for_comment))

    cov = r.coverage
    out.append("<details><summary>Coverage and limits</summary>\n")
    out.append(f"- Source trees scanned: {', '.join(cov.trees_scanned) or 'none'}")
    out.append(f"- Python files parsed: {cov.python_files_parsed} (skipped by relevance filter: {cov.python_files_skipped_by_filter}); SQL files parsed: {cov.sql_files_parsed}; SQLAlchemy models found: {cov.models_found}")
    if cov.python_files_failed:
        out.append(f"- Python files that could not be parsed ({len(cov.python_files_failed)}): " + ", ".join(cov.python_files_failed[:10]))
    if cov.files_skipped_too_large:
        out.append(f"- Files skipped as too large ({len(cov.files_skipped_too_large)}): " + ", ".join(cov.files_skipped_too_large[:10]))
    if cov.unanalyzed_files_by_ext:
        out.append("- Not analysed (V1 supports Python/SQLAlchemy and SQL only): " + ", ".join(f"{n} {e}" for e, n in sorted(cov.unanalyzed_files_by_ext.items())) + " files")
    for n in cov.notes:
        out.append(f"- {n}")
    out.append("- Only CONFIRMED findings can fail the check. POSSIBLE and UNKNOWN findings are advisory; absence of a finding is not proof of safety.")
    out.append("\n</details>")
    text = "\n".join(out)
    if for_comment and len(text) > MAX_COMMENT:
        text = text[:MAX_COMMENT].rsplit("\n", 1)[0] + "\n\n_Report truncated; see the CI log or SARIF output for the full list._"
    return text


def to_text(r: Report) -> str:
    out = [f"DCI {r.version}: {_verdict(r)} ({_counts(r)})"]
    for f in sorted(r.findings, key=lambda f: (f.severity != Severity.ERROR, f.file, f.line)):
        out.append(f"\n[{f.rule_id}] {f.severity.value.upper()} {f.confidence.value}: {f.title}")
        if f.file:
            out.append(f"  at {f.file}:{f.line}  {f.change.describe() if f.change else ''}")
        out.append(f"  {f.message}")
        for e in f.evidence[:10]:
            out.append(f"    - {e.file}:{e.line} [{e.via}/{e.confidence.value}] {e.snippet}")
        if f.total_evidence > min(10, len(f.evidence)):
            out.append(f"    ... {f.total_evidence} total")
        for i, s in enumerate(f.recommendation, 1):
            out.append(f"  {i}. {s}")
        if f.ai:
            out.append(f"  AI (advisory): {_AI_LABEL.get(f.ai.verdict, f.ai.verdict)}. {f.ai.summary}")
            for c in f.ai.citations:
                out.append(f"    cited {c['file']}:{c['line']}: {c['quote']}")
            if f.ai.suggested_fix:
                out.append(f"    AI-suggested fix: {f.ai.suggested_fix}")
    for n in r.coverage.notes:
        out.append(f"\nnote: {n}")
    return "\n".join(out)


def _enc(o):
    if hasattr(o, "value"):
        return o.value
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    raise TypeError(type(o))


def to_json(r: Report) -> str:
    d = asdict(r)
    d["schema_version"] = 1
    d["verdict"] = _verdict(r)
    d["blocking_count"] = len(r.blocking())
    return json.dumps(d, default=_enc, indent=2, sort_keys=True)


def to_sarif(r: Report) -> str:
    rules = {}
    results = []
    level = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.INFO: "note"}
    for f in r.findings:
        rules.setdefault(f.rule_id, {"id": f.rule_id, "name": f.title, "shortDescription": {"text": f.title}})
        res = {
            "ruleId": f.rule_id,
            "level": level[f.severity],
            "message": {"text": f"{f.message} [confidence: {f.confidence.value}]"},
            "properties": {"confidence": f.confidence.value, "evidenceCount": f.total_evidence},
        }
        if f.ai:
            res["properties"]["aiAdvisory"] = {"verdict": f.ai.verdict, "summary": f.ai.summary, "suggestedFix": f.ai.suggested_fix}
        if f.file:
            res["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": max(1, f.line)}}}]
        rel = [e for e in f.evidence if e.tree == "head"]
        if rel:
            res["relatedLocations"] = [
                {"id": i, "physicalLocation": {"artifactLocation": {"uri": e.file}, "region": {"startLine": max(1, e.line)}},
                 "message": {"text": f"{e.via}: {e.snippet}"}}
                for i, e in enumerate(rel)
            ]
        results.append(res)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "dci", "version": r.version, "rules": list(rules.values())}}, "results": results}],
    }
    return json.dumps(doc, indent=2)
