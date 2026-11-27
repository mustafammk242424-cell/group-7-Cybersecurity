from unittest.mock import MagicMock, patch

from pysec_hybrid_inspector_v2 import PySecHybridInspectorV2


def _make_response(status_code: int, text: str = "", headers: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    return resp


def test_vulnerable_target_detected() -> None:
    inspector = PySecHybridInspectorV2(target_url="http://localhost:3000")

    def fake_get(url, timeout):
        # 缺少 CSP / X-Frame-Options / X-Content-Type-Options 且帶有 *
        return _make_response(
            200,
            text="<html>Juice Shop</html>",
            headers={"Access-Control-Allow-Origin": "*"},
        )

    def fake_post(url, json=None, data=None, headers=None, timeout=5):
        if "/rest/user/login" in url:
            return _make_response(500, text="SQLITE_ERROR: near '1': syntax error")
        return _make_response(200, text="Authorized without auth")

    with patch.object(inspector.session, "get", side_effect=fake_get), patch.object(
        inspector.session, "post", side_effect=fake_post
    ):
        report = inspector.run_all()
        assert report["metrics"]["vulnerable_count"] >= 3
        print("[PASS] Vulnerable scenario correctly flagged:", report["metrics"])


def test_hardened_target_passes() -> None:
    inspector = PySecHybridInspectorV2(target_url="http://localhost:5000")

    hardened_headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Access-Control-Allow-Origin": "http://localhost:5000",
    }

    def fake_get(url, timeout):
        return _make_response(200, text="OK", headers=hardened_headers)

    def fake_post(url, json=None, data=None, headers=None, timeout=5):
        if "/rest/user/login" in url:
            return _make_response(401, text='{"error":"Invalid credentials"}')
        return _make_response(503, text='{"error":"Service Unavailable"}')

    with patch.object(inspector.session, "get", side_effect=fake_get), patch.object(
        inspector.session, "post", side_effect=fake_post
    ):
        report = inspector.run_all(
            header_path="/",
            sqli_endpoint="/rest/user/login",
            resilience_endpoint="/api/protected",
        )
        assert report["metrics"]["vulnerable_count"] == 0
        assert report["metrics"]["secure_count"] == report["metrics"]["total_findings"]
        print("[PASS] Hardened scenario cleanly verified as Secure:", report["metrics"])


if __name__ == "__main__":
    test_vulnerable_target_detected()
    test_hardened_target_passes()