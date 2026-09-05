"""
geo_lookup.py

Resolves an IP address to geolocation + infrastructure info.
Tries a live lookup (ip-api.com, free tier, no key) with a short timeout.
Falls back to a hardcoded dict for our known sample-email IPs so the demo
NEVER depends on internet access or a third-party API being up during judging.
"""

import requests

# Hardcoded fallback so the demo works fully offline. Populated for the
# earliest-external-IP values baked into our sample .eml files.
FALLBACK_GEO = {
    "185.220.101.47": {  # phishing_paypal.eml
        "country": "Germany",
        "city": "Frankfurt",
        "lat": 50.1109,
        "lon": 8.6821,
        "isp": "Datacenter / Hosting Provider (Tor exit-node range)",
        "is_hosting_or_vpn": True,
    },
    "45.142.212.88": {  # bec_ceo_wire.eml
        "country": "Netherlands",
        "city": "Amsterdam",
        "lat": 52.3676,
        "lon": 4.9041,
        "isp": "Offshore VPS Hosting",
        "is_hosting_or_vpn": True,
    },
    "103.224.182.19": {  # phishing_creds.eml
        "country": "India",
        "city": "Mumbai",
        "isp": "Shared/Free Hosting Provider",
        "lat": 19.0760,
        "lon": 72.8777,
        "is_hosting_or_vpn": True,
    },
}

DEFAULT_UNKNOWN = {
    "country": "Unknown",
    "city": "Unknown",
    "lat": 0.0,
    "lon": 0.0,
    "isp": "Unknown",
    "is_hosting_or_vpn": False,
}


def get_geo(ip: str | None) -> dict:
    """
    Returns geolocation info for an IP. Never raises — always returns a dict,
    falling back to hardcoded data or a safe 'unknown' default so the app
    never crashes or hangs during a live demo.
    """
    if not ip:
        return {**DEFAULT_UNKNOWN, "source": "no_ip_found"}

    if ip in FALLBACK_GEO:
        # Try live lookup first (nicer for judges if wifi works), but we
        # already know the fallback is good, so keep the timeout very short.
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=1.5)
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "lat": data.get("lat", 0.0),
                    "lon": data.get("lon", 0.0),
                    "isp": data.get("isp", "Unknown"),
                    "is_hosting_or_vpn": bool(data.get("hosting", False)),
                    "source": "live_lookup",
                }
        except Exception:
            pass
        return {**FALLBACK_GEO[ip], "source": "offline_fallback"}

    # Unknown IP (e.g. custom uploaded email) — try live lookup, else unknown
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=1.5)
        data = resp.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "lat": data.get("lat", 0.0),
                "lon": data.get("lon", 0.0),
                "isp": data.get("isp", "Unknown"),
                "is_hosting_or_vpn": bool(data.get("hosting", False)),
                "source": "live_lookup",
            }
    except Exception:
        pass

    return {**DEFAULT_UNKNOWN, "source": "unavailable"}


if __name__ == "__main__":
    for ip in list(FALLBACK_GEO.keys()) + [None]:
        print(ip, "->", get_geo(ip))
