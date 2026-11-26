"""Validation and fallback formatting for AI-generated explanations."""

import re
from typing import Any

from ..data import BASELINE_RECOMMENDATIONS, LIMITATIONS

_INSPECTION_RE = re.compile(
    r"\b(visited|opened|inspected|browsed|page content|rendered|crawled|downloaded the page)\b",
    re.IGNORECASE,
)
_RISK_TERMS_RE = re.compile(
    r"\b(risk level|score of|\b\d+%\b|\bpercentage\b)\b",
    re.IGNORECASE,
)
_DEFINITIVE_SAFETY_RE = re.compile(
    r"\b(completely safe|verified safe|entirely safe|guaranteed safe|is safe|confirmed safe|"
    r"safe to (browse|visit|use)|safe site|declared safe|marked safe|definitely safe|"
    r"100% safe|not phishing|no threat|no risk|zero risk|benign|harmless|\bsafe\b)\b",
    re.IGNORECASE,
)
_UNSUPPORTED_VERDICTS_RE = re.compile(
    r"\b(confirmed phishing|guaranteed phishing|definitely phishing|proven malicious|"
    r"confirmed malicious|dangerous site|phishing website|malicious site|high[ -]risk|suspicious|low[ -]risk)\b",
    re.IGNORECASE,
)


def build_fallback_explanation(
    evidence: list[dict[str, Any]],
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    """Construct a deterministic fallback explanation directly from backend evidence."""
    if evidence:
        high_or_med = [e for e in evidence if e.get("severity") in ("high", "medium")]
        selected = high_or_med if high_or_med else evidence
        reasons = [
            {"text": e["description"], "evidence_refs": [e["ref"]]}
            for e in selected
        ]
        summary = f"Evaluation identified {len(evidence)} structural indicator(s) in the URL."
    else:
        reasons = [
            {
                "text": "No notable suspicious indicators were detected in the URL structure.",
                "evidence_refs": [],
            }
        ]
        summary = "No strong suspicious indicators found during URL analysis."

    return {
        "summary": summary[:300],
        "reasons": reasons,
        "recommendations": list(BASELINE_RECOMMENDATIONS),
        "limitations": list(limitations or LIMITATIONS),
        "validation_status": "fallback",
    }


def validate_ai_response(
    raw_response: dict[str, Any] | None,
    known_evidence_refs: set[str],
    accessibility_status: str,
    evidence: list[dict[str, Any]],
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    """Enforce design §5 contract on Gemini explanation output.

    Rules:
    1. Drop any reason with missing/unknown evidence refs.
    2. Drop any text claiming page was visited/inspected if accessibility_status != 'accessible'.
    3. Drop risk-level or percentage claims.
    4. If no valid reasons remain or on format error -> fallback explanation.
    5. Always append fixed baseline recommendations.
    """
    if not isinstance(raw_response, dict):
        return build_fallback_explanation(evidence, limitations)

    summary = raw_response.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return build_fallback_explanation(evidence, limitations)

    # Check summary for forbidden claims
    if accessibility_status != "accessible" and _INSPECTION_RE.search(summary):
        return build_fallback_explanation(evidence, limitations)
    if _RISK_TERMS_RE.search(summary):
        return build_fallback_explanation(evidence, limitations)
    if _DEFINITIVE_SAFETY_RE.search(summary) or _UNSUPPORTED_VERDICTS_RE.search(summary):
        return build_fallback_explanation(evidence, limitations)

    reasons_in = raw_response.get("reasons")
    if not isinstance(reasons_in, list):
        return build_fallback_explanation(evidence, limitations)

    valid_reasons = []
    was_filtered = False

    for r in reasons_in:
        if not isinstance(r, dict):
            was_filtered = True
            continue

        text = r.get("text")
        refs = r.get("evidence_refs")

        if not isinstance(text, str) or not text.strip():
            was_filtered = True
            continue

        if not isinstance(refs, list) or not refs:
            was_filtered = True
            continue

        # Reject reasons citing unknown or missing refs
        if not all(ref in known_evidence_refs for ref in refs):
            was_filtered = True
            continue

        # Reject reasons claiming inspection when not accessible
        if accessibility_status != "accessible" and _INSPECTION_RE.search(text):
            was_filtered = True
            continue

        # Reject reasons stating risk scores or percentages
        if _RISK_TERMS_RE.search(text):
            was_filtered = True
            continue

        # Reject unsupported safety claims or definitive verdicts
        if _DEFINITIVE_SAFETY_RE.search(text) or _UNSUPPORTED_VERDICTS_RE.search(text):
            was_filtered = True
            continue

        valid_reasons.append({"text": text.strip(), "evidence_refs": refs})

    # If no valid reasons remain, fallback to evidence descriptions
    if not valid_reasons:
        return build_fallback_explanation(evidence, limitations)

    # Recommendations: preserve valid Gemini recommendations, always include baseline recommendations
    raw_recs = raw_response.get("recommendations", [])
    recommendations: list[str] = []
    if isinstance(raw_recs, list):
        for rec in raw_recs:
            if (
                isinstance(rec, str)
                and rec.strip()
                and not _INSPECTION_RE.search(rec)
                and not _DEFINITIVE_SAFETY_RE.search(rec)
                and not _UNSUPPORTED_VERDICTS_RE.search(rec)
            ):
                recommendations.append(rec.strip())

    for base_rec in BASELINE_RECOMMENDATIONS:
        if base_rec not in recommendations:
            recommendations.append(base_rec)

    # Limitations: ensure baseline limitations
    raw_lims = raw_response.get("limitations", [])
    output_limitations: list[str] = []
    if isinstance(raw_lims, list):
        for lim in raw_lims:
            if isinstance(lim, str) and lim.strip():
                output_limitations.append(lim.strip())

    for base_lim in (limitations or LIMITATIONS):
        if base_lim not in output_limitations:
            output_limitations.append(base_lim)

    status = "filtered" if was_filtered else "validated"

    return {
        "summary": summary.strip()[:300],
        "reasons": valid_reasons,
        "recommendations": recommendations,
        "limitations": output_limitations,
        "validation_status": status,
    }
