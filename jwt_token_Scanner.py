from flask import Flask, request, render_template_string
import base64
import json
import datetime

app = Flask(__name__)

HTML_TEMPLATE = """
<!doctype html>
<html>
<head><title>JWT Vulnerability Scanner</title></head>
<body>
    <h2>JWT Vulnerability Scanner</h2>
    <form method="post">
        <textarea name="token" rows="6" cols="80" placeholder="Paste your JWT token here"></textarea><br><br>
        <input type="submit" value="Scan Token">
    </form>
    {% if report %}
        <h3>Vulnerability Report:</h3>
        <ul>{% for item in report %}<li>{{ item }}</li>{% endfor %}</ul>
    {% endif %}
</body>
</html>
"""

def decode_segment(segment):
    try:
        padding = '=' * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(segment + padding))
    except:
        return {}

def scan_jwt(token):
    parts = token.split('.')
    if len(parts) != 3:
        return ["Invalid JWT format."]
    header, payload, signature = decode_segment(parts[0]), decode_segment(parts[1]), parts[2]
    report = []

    # Algorithm checks
    alg = header.get("alg", "").lower()
    if alg == "none":
        report.append("⚠️ Uses 'none' algorithm (unsigned).")
    if alg in ["md5", "sha1"]:
        report.append(f"⚠️ Uses deprecated algorithm: {alg}.")

    # Expiration checks
    if "exp" not in payload:
        report.append("⚠️ Missing 'exp' claim.")
    else:
        try:
            exp_time = datetime.datetime.fromtimestamp(payload["exp"])
            if (exp_time - datetime.datetime.utcnow()).days > 30:
                report.append(f"⚠️ Long lifetime: {exp_time}")
        except:
            report.append("⚠️ Invalid 'exp' format.")

    # JWT ID check
    if "jti" not in payload:
        report.append("⚠️ Missing 'jti' claim.")

    # Scope checks
    if "scope" in payload and any(s in str(payload["scope"]).lower() for s in ["admin", "*"]):
        report.append(f"⚠️ Dangerous scope: {payload['scope']}")

    # Sensitive data check
    if any(k in json.dumps(payload).lower() for k in ["password", "secret", "key", "token"]):
        report.append("⚠️ Sensitive data found in payload.")

    # Signature check
    if len(signature) < 20:
        report.append("⚠️ Weak signature.")

    # Privilege escalation checks
    for claim in ["role", "roles", "username","permissions", "groups"]:
        if claim in payload:
            value = str(payload[claim]).lower()
            if any(priv in value for priv in ["admin", "superuser", "root", "test" , "*" ]):
                report.append(f"⚠️ Potential privilege escalation via '{claim}': {payload[claim]}")

    return report or ["✅ No obvious vulnerabilities found."]

@app.route('/', methods=['GET', 'POST'])
def index():
    report = None
    if request.method == 'POST':
        token = request.form.get('token', '')
        report = scan_jwt(token)
    return render_template_string(HTML_TEMPLATE, report=report)

if __name__ == '__main__':
    app.run(debug=True)
