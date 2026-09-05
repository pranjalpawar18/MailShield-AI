"""
scorer.py

Converts header forensics output into a 0-100 "header risk score".
Weights are deliberately simple and transparent (not a black box) so they
can be explained to judges and tuned easily.
"""

WEIGHTS = {
    "spf_fail": 25,
    "dkim_fail": 20,
    "dmarc_fail": 20,
    "return_path_mismatch": 20,
    "reply_to_mismatch": 15,
    "no_received_headers": 15,
}


def header_risk_score(forensics: dict) -> dict:
    """
    Returns {"score": int 0-100, "contributions": [{"reason": str, "points": int}]}
    """
    contributions = []

    if forensics.get("spf") in ("fail", "softfail"):
        contributions.append({"reason": "SPF authentication failed", "points": WEIGHTS["spf_fail"]})
    if forensics.get("dkim") in ("fail", "none"):
        contributions.append({"reason": "DKIM signature missing or invalid", "points": WEIGHTS["dkim_fail"]})
    if forensics.get("dmarc") == "fail":
        contributions.append({"reason": "DMARC policy failed", "points": WEIGHTS["dmarc_fail"]})

    if (forensics.get("return_path_domain") and forensics.get("from_domain")
            and forensics["return_path_domain"] != forensics["from_domain"]):
        contributions.append({
            "reason": "Return-Path domain mismatch with From address",
            "points": WEIGHTS["return_path_mismatch"],
        })

    if (forensics.get("reply_to_domain") and forensics.get("from_domain")
            and forensics["reply_to_domain"] != forensics["from_domain"]):
        contributions.append({
            "reason": "Reply-To domain differs from From address",
            "points": WEIGHTS["reply_to_mismatch"],
        })

    if not forensics.get("hops"):
        contributions.append({
            "reason": "No routing (Received header) chain found",
            "points": WEIGHTS["no_received_headers"],
        })

    total = min(100, sum(c["points"] for c in contributions))
    return {"score": total, "contributions": contributions}


if __name__ == "__main__":
    from header_forensics import analyze_eml
    import glob, os

    for path in sorted(glob.glob("data/sample_emails/*.eml")):
        f = analyze_eml(path)
        s = header_risk_score(f)
        print(f"{os.path.basename(path):30s} header_risk={s['score']:3d}  "
              f"spf={f['spf']:8s} dkim={f['dkim']:8s} dmarc={f['dmarc']:8s} "
              f"ip={f['earliest_external_ip']}")
