"""
fusion.py

Combines the three independent signal sources into one final 0-100 fraud
score and verdict:
  - header_score   (from scorer.py, based on SPF/DKIM/DMARC + mismatches)
  - ml_confidence   (from classifier.py, based on NLP content analysis)
  - geo_risk        (derived here, based on hosting/VPN infrastructure flag)

Weights are explicit constants so they can be explained and tuned on the fly
in front of judges if asked "why 40/35/25?".
"""

WEIGHT_ML = 0.40
WEIGHT_HEADER = 0.35
WEIGHT_GEO = 0.25


def _geo_risk_score(geo: dict) -> int:
    """Simple geo risk heuristic: hosting/VPN/datacenter infra = high risk."""
    if geo.get("is_hosting_or_vpn"):
        return 90
    if geo.get("country") == "Unknown":
        return 30  # no info is mildly suspicious, not damning
    return 10


def compute_fraud_score(header_score: int, ml_result: dict, geo: dict) -> dict:
    ml_score = ml_result["confidence"]
    geo_score = _geo_risk_score(geo)

    final = (WEIGHT_ML * ml_score) + (WEIGHT_HEADER * header_score) + (WEIGHT_GEO * geo_score)
    final = round(min(100, max(0, final)))

    if final >= 70:
        verdict = "Phishing / Fraud (High Confidence)"
    elif final >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Legitimate"

    return {
        "final_score": final,
        "verdict": verdict,
        "breakdown": {
            "ml_contribution": round(WEIGHT_ML * ml_score, 1),
            "header_contribution": round(WEIGHT_HEADER * header_score, 1),
            "geo_contribution": round(WEIGHT_GEO * geo_score, 1),
        },
        "raw_signals": {
            "ml_confidence": ml_score,
            "header_risk_score": header_score,
            "geo_risk_score": geo_score,
        },
    }


if __name__ == "__main__":
    import glob, os
    from header_forensics import analyze_eml
    from scorer import header_risk_score
    from classifier import predict
    from geo_lookup import get_geo

    for path in sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "data", "sample_emails", "*.eml"))):
        f = analyze_eml(path)
        h = header_risk_score(f)
        ml = predict(f["subject"] + " " + f["body_text"])
        geo = get_geo(f["earliest_external_ip"])
        fusion = compute_fraud_score(h["score"], ml, geo)
        print(f"{os.path.basename(path):30s} FINAL={fusion['final_score']:3d}  "
              f"verdict={fusion['verdict']:35s} "
              f"(ml={fusion['raw_signals']['ml_confidence']}, "
              f"header={fusion['raw_signals']['header_risk_score']}, "
              f"geo={fusion['raw_signals']['geo_risk_score']})")
