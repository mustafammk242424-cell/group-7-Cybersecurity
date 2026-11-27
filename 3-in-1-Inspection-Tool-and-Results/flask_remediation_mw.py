import json
import logging
from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["DEBUG"] = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
audit_logger = logging.getLogger("sec_audit")

CSP_POLICY = "default-src 'self'; frame-ancestors 'none'"
ALLOWED_ORIGIN = "http://127.0.0.1:5000"


@app.after_request
def enforce_a02_headers(resp):
    # A02:2025 - 強制加入防禦標頭並限制跨域來源
    resp.headers["Content-Security-Policy"] = CSP_POLICY
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
    return resp


@app.route("/", methods=["GET"])
def index():
    return jsonify({"service": "Flask Remediation Middleware", "status": "hardened"}), 200


@app.route("/rest/user/login", methods=["POST"])
def hardened_login():
    # 示範受控登入端點：拒絕未驗證或異常輸入，不洩漏 SQL 錯誤細節
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data.get("email") or not data.get("password"):
        return jsonify({"error": "Bad Request"}), 400
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/protected", methods=["GET", "POST"])
def protected_endpoint():
    # A10:2025 - 遇到異常或缺少有效授權時採 Fail-Closed 阻斷並寫入結構化 JSON 日誌
    try:
        payload = request.get_json(force=False, silent=False)
        if not isinstance(payload, dict) or "token" not in payload:
            raise ValueError("Missing or invalid session token")
        return jsonify({"error": "Unauthorized"}), 401
    except Exception as exc:
        record = {
            "event": "AUTH_FAIL_CLOSED",
            "error_type": type(exc).__name__,
            "path": request.path,
            "method": request.method,
        }
        audit_logger.critical(json.dumps(record, ensure_ascii=False))
        return jsonify({"error": "Service Unavailable"}), 503


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
