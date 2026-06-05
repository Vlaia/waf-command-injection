from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route("/")
def index():
    return """
    <html>
    <head><title>Network Diagnostic Tool</title></head>
    <body>
        <h2>Network Diagnostic Tool</h2>
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

    # RANJIVO: direktno ubacivanje korisnickog unosa u shell komandu
    command = f"ping -c 2 {host}"
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=10)
        return jsonify({"command": command, "output": result.decode()})
    except subprocess.CalledProcessError as e:
        return jsonify({"command": command, "output": e.output.decode()}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 500

@app.route("/lookup")
def lookup():
    domain = request.args.get("domain", "")
    if not domain:
        return jsonify({"error": "Missing 'domain' parameter"}), 400

    # RANJIVO: direktno ubacivanje korisnickog unosa u shell komandu
    command = f"nslookup {domain}"
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=10)
        return jsonify({"command": command, "output": result.decode()})
    except subprocess.CalledProcessError as e:
        return jsonify({"command": command, "output": e.output.decode()}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 500

if __name__ == "__main__":
    print("[!] WARNING: This application is intentionally vulnerable. DO NOT deploy in production.")
    app.run(debug=True, port=5000)
