"""
header_forensics.py

Parses a raw .eml file and extracts:
- Return-Path, Reply-To, Message-ID, From
- The full Received header chain (in transit order)
- SPF / DKIM / DMARC results (from Authentication-Results)
- The earliest external (non-private) IP address in the Received chain
- A list of anomaly flags (spoofing / mismatch indicators)

Design note on "earliest external IP":
Received headers are prepended by each hop, so the header block, read top to
bottom, goes from MOST RECENT hop to OLDEST hop. We reverse the list so index 0
is the oldest (closest to the true origin), then walk forward and return the
first IP that is NOT a private/loopback/reserved address. That's our best
single-signal estimate of "where this email actually came from" before it
entered relay infrastructure we don't control.
"""

import re
import ipaddress
from email import message_from_string
from email.utils import parseaddr


IP_REGEX = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return True  # if we can't parse it, don't trust it as a public IP


def _extract_ip(received_header: str) -> str | None:
    """Pull the first IPv4 address out of a single Received header string."""
    matches = IP_REGEX.findall(received_header)
    for candidate in matches:
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return None


def _domain_of(address: str) -> str:
    """Extract domain from an email address like 'Name <user@domain.com>'."""
    _, addr = parseaddr(address or "")
    if "@" in addr:
        return addr.split("@", 1)[1].lower().strip()
    return ""


def parse_authentication_results(auth_header: str) -> dict:
    """Extract spf/dkim/dmarc verdicts from an Authentication-Results header."""
    result = {"spf": "none", "dkim": "none", "dmarc": "none"}
    if not auth_header:
        return result
    for key in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{key}\s*=\s*(\w+)", auth_header, re.IGNORECASE)
        if m:
            result[key] = m.group(1).lower()
    return result


def analyze_eml(file_path: str) -> dict:
    """Main entry point: parse an .eml file path and return a forensics dict."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    return analyze_raw(raw)


def analyze_raw(raw_content: str) -> dict:
    msg = message_from_string(raw_content)

    from_addr = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")
    message_id = msg.get("Message-ID", "")
    subject = msg.get("Subject", "")
    date = msg.get("Date", "")

    # Received headers: email library returns them in document order (top to
    # bottom = newest to oldest). Reverse so index 0 = oldest = closest to origin.
    received_headers = msg.get_all("Received", []) or []
    received_headers_oldest_first = list(reversed(received_headers))

    hops = []
    earliest_external_ip = None
    for idx, hop_text in enumerate(received_headers_oldest_first):
        ip = _extract_ip(hop_text)
        is_private = _is_private_ip(ip) if ip else True
        hops.append({
            "hop_index": idx,
            "raw": hop_text.strip().replace("\n", " "),
            "ip": ip,
            "is_private": is_private,
        })
        if ip and not is_private and earliest_external_ip is None:
            earliest_external_ip = ip

    auth_header = msg.get("Authentication-Results", "")
    auth_results = parse_authentication_results(auth_header)

    # Body text (best-effort, plain text preferred)
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body_text = part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
                except Exception:
                    body_text = part.get_payload()
                break
    else:
        body_text = msg.get_payload()

    # --- Anomaly detection ---
    anomalies = []
    from_domain = _domain_of(from_addr)
    return_path_domain = _domain_of(return_path)
    reply_to_domain = _domain_of(reply_to)

    if auth_results["spf"] in ("fail", "softfail"):
        anomalies.append(f"SPF check {auth_results['spf']} for sending domain")
    if auth_results["dkim"] in ("fail", "none"):
        anomalies.append(f"DKIM signature {auth_results['dkim']}")
    if auth_results["dmarc"] == "fail":
        anomalies.append("DMARC policy check failed")

    if return_path_domain and from_domain and return_path_domain != from_domain:
        anomalies.append(
            f"Return-Path domain ({return_path_domain}) does not match "
            f"From domain ({from_domain})"
        )
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        anomalies.append(
            f"Reply-To domain ({reply_to_domain}) differs from From domain "
            f"({from_domain}) - replies would go to a different address"
        )

    if len(received_headers_oldest_first) == 0:
        anomalies.append("No Received headers found - routing chain missing or stripped")

    return {
        "subject": subject,
        "from_addr": from_addr,
        "from_domain": from_domain,
        "return_path": return_path,
        "return_path_domain": return_path_domain,
        "reply_to": reply_to,
        "reply_to_domain": reply_to_domain,
        "message_id": message_id,
        "date": date,
        "body_text": body_text.strip(),
        "hops": hops,
        "earliest_external_ip": earliest_external_ip,
        "spf": auth_results["spf"],
        "dkim": auth_results["dkim"],
        "dmarc": auth_results["dmarc"],
        "anomalies": anomalies,
    }


if __name__ == "__main__":
    import sys, json
    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample_emails/phishing_paypal.eml"
    result = analyze_eml(path)
    print(json.dumps(result, indent=2, default=str))
