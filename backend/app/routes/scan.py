"""Scan API route per Lite specifications."""

import hashlib
import hmac
import os
import secrets
from typing import Any

from apiflask import APIBlueprint, Schema, abort
from apiflask.fields import Boolean, Float, Integer, List, Nested, String

from .. import api_key_auth
from ..errors import error_response
from ..scoring.aggregator import aggregate_scan_result
from ..services.gemini_service import explain_scan
from ..services.rule_scorer import evaluate_rules
from ..services.url_features import extract_features
from ..services.url_normalizer import InvalidUrlError, normalize_url

scan_bp = APIBlueprint("scan", __name__, tag="Scan")


# -----------------------------------------------------------------------------
# OpenAPI Schemas
# -----------------------------------------------------------------------------
class ScanInputSchema(Schema):
    url = String(
        required=True,
        metadata={
            "description": "URL to scan and assess for phishing threats.",
            "example": "http://paypal.secure-login.verify-account.xyz/update",
        },
    )
    include_ai_analysis = Boolean(
        load_default=True,
        metadata={
            "description": "Whether to request an AI threat explanation from Gemini.",
            "example": True,
        },
    )


class EvidenceItemSchema(Schema):
    ref = String(metadata={"example": "E1"})
    indicator = String(metadata={"example": "brand_in_subdomain_or_path"})
    severity = String(metadata={"example": "high"})
    description = String(
        metadata={
            "example": "The brand name 'paypal' appears in the subdomain, but registered domain is 'verify-account.xyz'."
        }
    )


class ReasonSchema(Schema):
    text = String(metadata={"example": "The URL structure mimics a well-known brand domain."})
    evidence_refs = List(String(), metadata={"example": ["E1"]})


class AIExplanationSchema(Schema):
    summary = String(metadata={"example": "Identified multiple high-risk indicators in the URL."})
    reasons = List(Nested(ReasonSchema))
    recommendations = List(String())
    limitations = List(String())
    validation_status = String(metadata={"example": "validated"})


class ScanResultDataSchema(Schema):
    classification = String(metadata={"example": "suspicious"})
    risk_score = Integer(metadata={"example": 55})
    confidence = Float(metadata={"example": 0.50})
    accessibility_status = String(metadata={"example": "not_attempted"})
    evidence = List(Nested(EvidenceItemSchema))
    limitations = List(String())
    ai_explanation = Nested(AIExplanationSchema, allow_none=True)


class ScanResponseSchema(Schema):
    success = Boolean(metadata={"example": True})
    scan_id = String(metadata={"example": "scn_a1b2c3d4e5f6g7h8"})
    status = String(metadata={"example": "completed"})
    result = Nested(ScanResultDataSchema)


class ErrorDetailSchema(Schema):
    code = String(metadata={"example": "unauthorized"})
    message = String(metadata={"example": "Invalid or missing API key."})
    request_id = String(metadata={"example": "req_1234567890ab"})


class StandardErrorSchema(Schema):
    success = Boolean(metadata={"example": False})
    error = Nested(ErrorDetailSchema)


# -----------------------------------------------------------------------------
# Route Handler
# -----------------------------------------------------------------------------
@scan_bp.post("/api/v1/scan/url")
@scan_bp.input(ScanInputSchema, arg_name="data")
@scan_bp.output(ScanResponseSchema, status_code=200)
@scan_bp.auth_required(api_key_auth)
@scan_bp.doc(
    summary="Analyze a URL for phishing threats",
    description=(
        "Scans a submitted URL against structural threat indicators (rules U01-U12, N01), "
        "determines the risk score and classification, and returns an AI explanation powered by Gemini."
    ),
    security="ApiKeyAuth",
    responses={
        200: "Scan completed successfully",
        401: "Unauthorized - invalid or missing X-API-Key",
        422: "Unprocessable Entity - invalid or malformed URL",
    },
)
def scan_url(data: dict[str, Any]):
    raw_url = data.get("url", "")
    include_ai = data.get("include_ai_analysis", True)

    # 1. Normalize and validate URL (Invalid URL -> 422)
    try:
        normalized = normalize_url(raw_url)
    except InvalidUrlError as exc:
        abort(422, message=str(exc), extra_data={"code": "invalid_url"})

    # 2. Extract structural features
    features = extract_features(normalized)

    # 3. Evaluate threat rules
    raw_score, evidence = evaluate_rules(features)

    # 4. Preliminary result without AI explanation
    preliminary = aggregate_scan_result(raw_score, evidence, ai_explanation=None)

    # 5. Gemini AI explanation if requested (Gemini failure never fails the scan)
    ai_explanation = None
    if include_ai:
        ai_explanation = explain_scan(normalized, preliminary)

    # 6. Final aggregated scan result
    final_result = aggregate_scan_result(raw_score, evidence, ai_explanation=ai_explanation)

    # 7. Generate public scan ID
    scan_id = f"scn_{secrets.token_urlsafe(16)}"

    return {
        "success": True,
        "scan_id": scan_id,
        "status": "completed",
        "result": final_result,
    }
