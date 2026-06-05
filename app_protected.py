from flask import Flask, request, jsonify
from waf import CommandInjectionWAF
import subprocess

app = Flask(__name__)

# Aktivacija WAF-a
waf = CommandInjectionWAF(app)

@app.route("/")
def index():
    return """
    <html>
    <head><title>Network Diagnostic Tool (Protected)</title></head>
    <body>
        <h2>Network Diagnostic Tool</h2>
        <p style="color:green"><b>[WAF ACTIVE]</b> Command Injection zastita je ukljucena.</p>
        <form action="/ping" method="get">
            <label>Host to ping:</label><br>
            <input type="text" name="host" placeholder="e.g. google.com" size="30">
            <input type="submit" value="Ping">
        </form>
        <br>
        <form action="/lookup" method="get">
            <label>DNS Lookup:</label><br>
            <input type="text" name="domain" placeholder="e.g. google.com" size="30">
            <input type="submit" value="Lookup">
        </form>
    </body>
    </html>
    """

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host:
        return jsonify({"error": "Missing 'host' parameter"}), 400

    # WAF je vec proverio - mozemo bezbedno koristiti parametar
    # Koristimo listu argumenata umesto shell=True (dodatna zastita)
    try:
        result = subprocess.check_output(
            ["ping", "-c", "2", host],
            stderr=subprocess.STDOUT,
            timeout=10
        )
        return jsonify({"output": result.decode()})
    except subprocess.CalledProcessError as e:
        return jsonify({"output": e.output.decode()}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 500

@app.route("/lookup")
def lookup():
    domain = request.args.get("domain", "")
    if not domain:
        return jsonify({"error": "Missing 'domain' parameter"}), 400

    try:
        result = subprocess.check_output(
            ["nslookup", domain],
            stderr=subprocess.STDOUT,
            timeout=10
        )
        return jsonify({"output": result.decode()})
    except subprocess.CalledProcessError as e:
        return jsonify({"output": e.output.decode()}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 500

if __name__ == "__main__":
    print("[*] WAF is ACTIVE. Command Injection attacks will be blocked.")
    app.run(debug=True, port=5001)
