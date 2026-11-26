"""Pure scoring aggregator per Lite scoring policy."""

from typing import Any

from ..data import LIMITATIONS


def classify_score(score: int) -> str:
    """Classify risk score into risk bands:

    score >= 70: high_risk
    40 <= score < 70: suspicious
    score < 40: low_risk
    """
    if score >= 70:
        return "high_risk"
    if score >= 40:
        return "suspicious"
    return "low_risk"


def aggregate_scan_result(
    raw_score: int,
    evidence: list[dict[str, Any]],
    ai_explanation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Combine rule score, evidence, and fixed Lite policy metadata.

    Policy:
    - risk_score = clamp(raw_score, 0, 100)
    - confidence = 0.50 (fixed Lite)
    - accessibility_status = "not_attempted"
    - classification = low_risk | suspicious | high_risk
    - limitations = fixed 3 limitations
    """
    clamped_score = max(0, min(100, raw_score))
    classification = classify_score(clamped_score)

    return {
        "classification": classification,
        "risk_score": clamped_score,
        "confidence": 0.50,
        "accessibility_status": "not_attempted",
        "evidence": evidence,
        "limitations": list(LIMITATIONS),
        "ai_explanation": ai_explanation,
    }
