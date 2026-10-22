import json, pathlib
import numpy as np, joblib
from datetime import datetime
from flask import Flask, jsonify, Response

BASE = pathlib.Path(__file__).resolve().parent.parent
THRESHOLD = 0.2      # chosen on Day 5
BLOCK_AFTER = 3      # login attempts before an IP is blocked

FEATURES = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

model = joblib.load(BASE / "data" / "rf_model.pkl")
X = np.load(BASE / "data" / "X_test.npy")
y = np.load(BASE / "data" / "y_test.npy")      # 0 = attack, 1 = normal

try:
    import shap
    explainer = shap.TreeExplainer(model)
except Exception:
    explainer = None

def severity(p):
    return "High" if p >= 0.8 else "Medium" if p >= 0.5 else "Low"

def reasons(row):
    if explainer is None:
        return ["SHAP not available"]
    sv = explainer.shap_values(row.reshape(1, -1))
    s = sv[0][0] if isinstance(sv, list) else sv[0, :, 0]
    top = np.argsort(-np.abs(s))[:3]
    return [FEATURES[i] + (" raises" if s[i] > 0 else " lowers") + " risk" for i in top]

app = Flask(__name__)

@app.route("/api/alerts")
def alerts():
    idx = np.random.choice(len(X), 30, replace=False)
    p = model.predict_proba(X[idx])[:, 0]          # probability of attack
    out = []
    for i, pa in zip(idx, p):
        if pa >= THRESHOLD:
            out.append({"time": datetime.now().strftime("%H:%M:%S"),
                        "p_attack": round(float(pa), 2),
                        "severity": severity(pa),
                        "really_attack": bool(y[i] == 0),
                        "why": reasons(X[i])})
    out.sort(key=lambda a: -a["p_attack"])
    return jsonify(out)

@app.route("/api/honeypot")
def honeypot():
    path = BASE / "logs" / "honeypot.jsonl"
    events = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except Exception:
                pass
    attempts = {}
    for e in events:
        if e.get("event") == "login_attempt":
            attempts[e["src_ip"]] = attempts.get(e["src_ip"], 0) + 1
    blocked = sorted(ip for ip, n in attempts.items() if n >= BLOCK_AFTER)
    (BASE / "logs").mkdir(exist_ok=True)
    (BASE / "logs" / "blocked_ips.txt").write_text("\n".join(blocked), encoding="utf-8")
    return jsonify({"events": events[-15:][::-1], "total": len(events), "blocked": blocked})

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>AI-IDS Dashboard</title>
<style>
body{font-family:Segoe UI,Arial;margin:20px;background:#f4f6f8}
h1{margin:0 0 15px} .grid{display:grid;grid-template-columns:1fr 1fr;gap:15px}
.card{background:#fff;padding:15px;border-radius:8px;box-shadow:0 1px 4px #0002}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:5px;border-bottom:1px solid #eee;text-align:left}
.High{color:#c0392b;font-weight:bold}.Medium{color:#e67e22;font-weight:bold}.Low{color:#27ae60}
.block{background:#fdecea;padding:6px;margin:4px 0;border-radius:4px}
</style></head><body>
<h1>Hybrid AI Intrusion Detection and Deception Platform</h1>
<div class="grid">
<div class="card"><h3>AI alerts (Random Forest + SHAP)</h3><table id="a"></table></div>
<div class="card"><h3>Honeypot activity (<span id="t">0</span> events)</h3><table id="h"></table>
<h3>Blocked IPs (auto-response)</h3><div id="b"></div></div>
</div>
<script>
async function load(){
 let a = await (await fetch('/api/alerts')).json();
 document.getElementById('a').innerHTML =
  '<tr><th>Time</th><th>P(attack)</th><th>Severity</th><th>Real label</th><th>Why</th></tr>' +
  a.map(x => '<tr><td>'+x.time+'</td><td>'+x.p_attack+'</td><td class="'+x.severity+'">'+x.severity+
   '</td><td>'+(x.really_attack?'attack':'normal')+'</td><td>'+x.why.join('; ')+'</td></tr>').join('');
 let h = await (await fetch('/api/honeypot')).json();
 document.getElementById('t').textContent = h.total;
 document.getElementById('h').innerHTML =
  '<tr><th>Time</th><th>Service</th><th>IP</th><th>Event</th><th>Details</th></tr>' +
  h.events.map(e => '<tr><td>'+e.time.slice(11)+'</td><td>'+e.service+'</td><td>'+e.src_ip+'</td><td>'+e.event+
   '</td><td>'+(e.username?e.username+' / '+e.password:(e.path||''))+'</td></tr>').join('');
 document.getElementById('b').innerHTML = h.blocked.length ?
  h.blocked.map(ip => '<div class="block">BLOCKED: '+ip+'</div>').join('') : 'None yet';
}
load(); setInterval(load, 5000);
</script></body></html>"""

@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)