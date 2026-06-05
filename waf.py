import re
import logging
from datetime import datetime

# Konfiguracija logovanja
logging.basicConfig(
    filename="waf.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------------------------------------------------------------
# Blacklista opasnih karaktera i kljucnih reci
# ---------------------------------------------------------------
DANGEROUS_CHARS = [
    ";", "&&", "||", "|", "`",
    "$(", "${", "\n", "\r",
    ">", ">>", "<", "2>",
]

DANGEROUS_KEYWORDS = [
    "cat", "ls", "pwd", "whoami", "id", "uname",
    "wget", "curl", "nc", "netcat", "bash", "sh",
    "python", "perl", "ruby", "php",
    "rm", "mv", "cp", "chmod", "chown",
    "etc/passwd", "etc/shadow", "/bin/",
    "base64", "echo", "printf",
]

# Regex obrasci za naprednu detekciju
DANGEROUS_PATTERNS = [
    re.compile(r"[;&|`]"),                          # Shell operatori
    re.compile(r"\$\(.*\)"),                        # Command substitution $(...)
    re.compile(r"`.*`"),                            # Backtick substitution
    re.compile(r"\|\s*\w+"),                        # Pipe + komanda
    re.compile(r">\s*\S+"),                         # Redirekcija outputa
    re.compile(r"<\s*\S+"),                         # Redirekcija inputa
    re.compile(r"\d+\s*>\s*&\s*\d+"),              # File descriptor redirect
    re.compile(r"\\x[0-9a-fA-F]{2}"),              # Hex enkodiranje
    re.compile(r"%[0-9a-fA-F]{2}"),                # URL enkodiranje opasnih karaktera
    re.compile(r"\.\./"),                           # Path traversal pokusaj
]

# ---------------------------------------------------------------
# Whitelist validacija za specificne parametre
# ---------------------------------------------------------------
WHITELISTS = {
    "host": re.compile(r"^[a-zA-Z0-9.\-]{1,253}$"),      # Validna IP ili hostname
    "domain": re.compile(r"^[a-zA-Z0-9.\-]{1,253}$"),    # Validni DNS domen
}


class WAFViolation(Exception):
    """Podignuta kada WAF detektuje napad."""
    def __init__(self, reason, payload):
        self.reason = reason
        self.payload = payload
        super().__init__(f"WAF blocked: {reason}")


class CommandInjectionWAF:
    """
    WAF middleware za detekciju i blokiranje Command Injection napada.

    Napadac moze pokusati da injektuje OS komande kroz korisnicke parametre,
    npr: host=google.com; cat /etc/passwd

    WAF primenjuje visestruke slojeve zastite:
      1. Whitelist validacija (najstrozija provera)
      2. Blacklista opasnih karaktera
      3. Blacklista opasnih kljucnih reci
      4. Regex detekcija naprednih obrazaca
    """

    def __init__(self, app):
        self.app = app
        app.before_request(self._inspect_request)

    def _inspect_request(self):
        from flask import request, jsonify

        for param_name, param_value in request.args.items():
            try:
                self._validate_param(param_name, param_value)
            except WAFViolation as e:
                self._log_attack(request, param_name, param_value, e.reason)
                return jsonify({
                    "error": "Request blocked by WAF",
                    "reason": e.reason,
                    "param": param_name,
                }), 403

    def _validate_param(self, name, value):
        # --- Sloj 1: Whitelist (ako postoji za ovaj parametar) ---
        if name in WHITELISTS:
            if not WHITELISTS[name].match(value):
                raise WAFViolation(
                    f"Whitelist validation failed for parameter '{name}'",
                    value
                )
            return  # Prosao whitelist - nema potrebe za daljim proverama

        # --- Sloj 2: Blacklista karaktera ---
        for char in DANGEROUS_CHARS:
            if char in value:
                raise WAFViolation(
                    f"Dangerous character detected: '{char}'",
                    value
                )

        # --- Sloj 3: Blacklista kljucnih reci ---
        value_lower = value.lower()
        for keyword in DANGEROUS_KEYWORDS:
            if keyword in value_lower:
                raise WAFViolation(
                    f"Dangerous keyword detected: '{keyword}'",
                    value
                )

        # --- Sloj 4: Regex obrasci ---
        for pattern in DANGEROUS_PATTERNS:
            if pattern.search(value):
                raise WAFViolation(
                    f"Dangerous pattern detected: '{pattern.pattern}'",
                    value
                )

    def _log_attack(self, request, param, value, reason):
        logging.warning(
            f"ATTACK BLOCKED | IP: {request.remote_addr} | "
            f"Path: {request.path} | Param: {param} | "
            f"Payload: {repr(value)} | Reason: {reason}"
        )
        print(f"[WAF] BLOCKED {request.remote_addr} -> {request.path}?"
              f"{param}={repr(value)} | {reason}")
