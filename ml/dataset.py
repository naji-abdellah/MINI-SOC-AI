"""Dataset Generation and Management for MiniSOC-AI Machine Learning Module.

Generates realistic, time-ordered, labeled SOC events combining normal traffic patterns
with various attack vectors under realistic class imbalance and non-trivial feature distributions.
"""

from datetime import datetime, timedelta, timezone
import random
from typing import List
import pandas as pd


# Benign URL paths with realistic parameters and noise
BENIGN_URLS = [
    "/",
    "/index.php",
    "/products",
    "/products/search?q=phone",
    "/products/search?q=laptop",
    "/products/search?q=headphones",
    "/products/search?q=O%27Reilly+Books",
    "/products/search?q=C%2B%2B+Programming",
    "/rest/products/search?q=apple",
    "/rest/products/search?q=banana&category=fruit",
    "/about.html",
    "/contact.us",
    "/login.php",
    "/rest/user/login",
    "/assets/main.css",
    "/assets/app.js",
    "/assets/vendor.bundle.js",
    "/images/logo.png",
    "/favicon.ico",
    "/vulnerabilities/fi/?page=include.php",
    "/vulnerabilities/sqli/?id=1&Submit=Submit",
    "/vulnerabilities/sqli/?id=2&Submit=Submit",
    "/api/v1/user/profile",
    "/api/v1/health",
    "/cart/view",
    "/checkout",
    "/blog/posts/2026-announcement",
    "/docs/api-reference",
    "/terms-and-conditions",
]

BENIGN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

# Attack vectors
ATTACK_VECTORS = {
    "sqli": [
        "/vulnerabilities/sqli/?id=1' UNION SELECT null,version()--&Submit=Submit",
        "/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users--",
        "/vulnerabilities/sqli/?id=1' OR 1=1--&Submit=Submit",
        "/rest/products/search?q=' OR 1=1--",
        "/products?id=1; WAITFOR DELAY '0:0:5'--",
        "/api/items?id=-1 OR 2>1#",
    ],
    "lfi": [
        "/vulnerabilities/fi/?page=../../../../../../etc/passwd",
        "/vulnerabilities/fi/?page=../../../../../../etc/shadow",
        "/vulnerabilities/fi/?page=..%2f..%2f..%2fetc%2fpasswd",
        "/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=index.php",
        "/preview?file=../../../../windows/win.ini",
    ],
    "cmdi": [
        "/vulnerabilities/exec/?ip=127.0.0.1;cat /etc/passwd",
        "/vulnerabilities/exec/?ip=127.0.0.1; whoami",
        "/vulnerabilities/exec/?ip=127.0.0.1| /bin/sh",
        "/tools/ping?host=localhost; id;",
    ],
    "scanner": [
        "/nikto-test-page.html",
        "/phpinfo.php",
        "/admin/config.php",
        "/.env",
        "/.git/HEAD",
        "/wp-config.php",
        "/wp-admin/install.php",
    ],
    "brute_force": [
        "/rest/user/login",
        "/login.php",
        "/api/v1/auth",
    ],
}

SCANNER_UAS = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)",
    "gobuster/3.6",
    "DirBuster-1.0.0-RC1",
    "Hydra v9.5 (https://github.com/vanhauser-thc/thc-hydra)",
    "curl/8.4.0",
]


def generate_synthetic_soc_dataset(
    n_samples: int = 5000,
    attack_ratio: float = 0.08,
    seed: int = 42,
    base_time: datetime = datetime(2026, 11, 5, 0, 0, 0, tzinfo=timezone.utc),
) -> pd.DataFrame:
    """Generate realistic SOC dataset without fixed-IP identity cheating.

    Realistic characteristics:
    - Benign requests and attacks share overlapping IP subnets (corporate proxies, NAT gateways).
    - Benign traffic has realistic error rates (404s on missing assets, 401 on expired tokens).
    - Attacks originate from distributed ranges (botnets, residential proxies) rather than single static IPs.
    """
    rng = random.Random(seed)
    records: List[dict] = []

    current_time = base_time
    n_attacks = int(n_samples * attack_ratio)
    n_benign = n_samples - n_attacks

    # Shared IP pool: internal clients, corporate proxies, and external visitors
    shared_ips = [f"192.168.1.{i}" for i in range(10, 80)]
    external_ips = [f"203.0.113.{i}" for i in range(1, 100)] + [f"198.51.100.{i}" for i in range(1, 100)]
    all_ip_pool = shared_ips + external_ips

    events_meta = [("benign", "benign")] * n_benign
    attack_types = ["sqli", "lfi", "cmdi", "scanner", "brute_force"]
    for _ in range(n_attacks):
        atype = rng.choice(attack_types)
        events_meta.append(("attack", atype))

    rng.shuffle(events_meta)

    for is_attack, atype in events_meta:
        current_time += timedelta(milliseconds=rng.randint(150, 2500))

        if is_attack == "benign":
            # 80% shared internal/external, 20% random internet visitor
            ip = rng.choice(all_ip_pool)
            url = rng.choice(BENIGN_URLS)
            method = "POST" if ("login" in url or "checkout" in url) else "GET"
            # Benign status codes: 82% 200, 10% 404 (typos/missing), 5% 302, 3% 401/403
            status_code = rng.choices([200, 404, 302, 401, 500], weights=[82, 10, 5, 2, 1])[0]
            ua = rng.choice(BENIGN_UAS)
            outcome = "success" if status_code < 400 else "failure"
            label = 0
            attack_name = "benign"
        else:
            # Attacks come from diverse rotating external IPs and occasional compromised internal IPs
            ip = rng.choice(external_ips) if rng.random() > 0.15 else rng.choice(shared_ips)
            url = rng.choice(ATTACK_VECTORS[atype])

            if atype == "scanner":
                ua = rng.choice(SCANNER_UAS)
                method = "GET"
                # Scanners hit non-existent paths (404/403)
                status_code = rng.choices([404, 403, 200], weights=[65, 30, 5])[0]
            elif atype == "brute_force":
                # Brute force often spoofs benign browser UA
                ua = rng.choice(BENIGN_UAS) if rng.random() > 0.3 else rng.choice(SCANNER_UAS)
                method = "POST"
                # Failed logins return 401, with occasional successful entry (200)
                status_code = rng.choices([401, 403, 200], weights=[85, 10, 5])[0]
            elif atype == "cmdi":
                ua = rng.choice(BENIGN_UAS + ["curl/8.4.0"])
                method = "POST" if "exec" in url else "GET"
                status_code = rng.choices([200, 500], weights=[70, 30])[0]
            elif atype == "sqli":
                ua = rng.choice(BENIGN_UAS) if rng.random() > 0.4 else "sqlmap/1.7.2#stable"
                method = "GET"
                status_code = rng.choices([200, 500, 400], weights=[75, 20, 5])[0]
            else:  # lfi
                ua = rng.choice(BENIGN_UAS)
                method = "GET"
                status_code = rng.choices([200, 404, 403], weights=[70, 20, 10])[0]

            outcome = "success" if status_code < 400 else "failure"
            label = 1
            attack_name = atype

        records.append({
            "timestamp": current_time,
            "source_ip": ip,
            "http_method": method,
            "http_url": url,
            "http_status_code": status_code,
            "http_user_agent": ua,
            "event_category": "web",
            "event_outcome": outcome,
            "label": label,
            "attack_type": attack_name,
        })

    df = pd.DataFrame(records)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df
