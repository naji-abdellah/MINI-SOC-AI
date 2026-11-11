"""Dataset Generation and Management for MiniSOC-AI Machine Learning Module.

Generates realistic, time-ordered, labeled SOC events combining normal traffic patterns
with various attack vectors under realistic class imbalance.
"""

from datetime import datetime, timedelta, timezone
import random
from typing import List, Tuple
import pandas as pd


# Benign URL paths and patterns
BENIGN_URLS = [
    "/",
    "/index.php",
    "/products",
    "/products/search?q=phone",
    "/products/search?q=laptop",
    "/products/search?q=headphones",
    "/rest/products/search?q=apple",
    "/rest/products/search?q=banana",
    "/about.html",
    "/contact.us",
    "/login.php",
    "/rest/user/login",
    "/assets/main.css",
    "/assets/app.js",
    "/images/logo.png",
    "/favicon.ico",
    "/vulnerabilities/fi/?page=include.php",
    "/vulnerabilities/sqli/?id=1&Submit=Submit",
    "/vulnerabilities/sqli/?id=2&Submit=Submit",
    "/api/v1/user/profile",
    "/cart/view",
    "/checkout",
]

BENIGN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
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
    """Generate a realistic, time-ordered, labeled dataset of SOC events."""
    random.seed(seed)
    records: List[dict] = []

    current_time = base_time
    n_attacks = int(n_samples * attack_ratio)
    n_benign = n_samples - n_attacks

    # Generate pool of normal IP addresses (internal and standard external clients)
    normal_ips = [f"192.168.1.{i}" for i in range(10, 60)]
    # Attacker IPs
    attacker_ips = {
        "sqli": "10.0.0.100",
        "lfi": "10.0.0.101",
        "cmdi": "10.0.0.102",
        "scanner": "10.0.0.103",
        "brute_force": "10.0.0.104",
    }

    # Interleave events with time increments
    # To mimic real-world bursts, we generate a continuous timeline
    events_meta = [("benign", "benign")] * n_benign

    # Distribute attacks across categories
    attack_types = ["sqli", "lfi", "cmdi", "scanner", "brute_force"]
    for i in range(n_attacks):
        atype = random.choice(attack_types)
        events_meta.append(("attack", atype))

    # Shuffle metadata while maintaining time increment progression
    random.shuffle(events_meta)

    for is_attack, atype in events_meta:
        # Time steps between 0.2s and 3.0s
        current_time += timedelta(milliseconds=random.randint(200, 3000))

        if is_attack == "benign":
            ip = random.choice(normal_ips)
            url = random.choice(BENIGN_URLS)
            method = "POST" if ("login" in url or "checkout" in url) else "GET"
            # Benign status codes: mostly 200, occasional 302 or 404
            status_code = random.choices([200, 302, 304, 404], weights=[85, 8, 4, 3])[0]
            ua = random.choice(BENIGN_UAS)
            outcome = "success" if status_code < 400 else "failure"
            label = 0
            attack_name = "benign"
            category = "web"
        else:
            ip = attacker_ips[atype]
            url = random.choice(ATTACK_VECTORS[atype])
            category = "web"
            if atype == "scanner":
                ua = random.choice(SCANNER_UAS)
                method = "GET"
                status_code = random.choices([403, 404, 200], weights=[60, 35, 5])[0]
            elif atype == "brute_force":
                ua = random.choice(BENIGN_UAS + [random.choice(SCANNER_UAS)])
                method = "POST"
                status_code = random.choices([401, 403, 200], weights=[85, 10, 5])[0]
            elif atype == "cmdi":
                ua = random.choice(BENIGN_UAS + ["curl/8.4.0"])
                method = "POST" if "exec" in url else "GET"
                status_code = random.choices([200, 500], weights=[70, 30])[0]
            else:
                ua = random.choice(BENIGN_UAS + [random.choice(SCANNER_UAS)])
                method = "GET"
                status_code = random.choices([200, 500, 400], weights=[80, 15, 5])[0]

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
            "event_category": category,
            "event_outcome": outcome,
            "label": label,
            "attack_type": attack_name,
        })

    df = pd.DataFrame(records)
    # Sort strictly by timestamp
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df
