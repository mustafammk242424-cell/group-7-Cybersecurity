import argparse
import json
import logging
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("PySecHybridInspectorV2")

DEFAULT_REQUIRED_HEADERS: List[str] = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]

DEFAULT_SQLI_PAYLOADS: List[str] = [
    "' OR 1=1--",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
]

SQL_ERROR_INDICATORS: List[str] = [
    "SQLITE_ERROR",
    "SQLITE_CONSTRAINT",
    "syntax error",
    "sqlite3.OperationalError",
    "ORA-",
    "MySQLSyntaxErrorException",
    "PostgreSQL",
]

# 用於測試 A10:2025 例外處理／Fail-Closed 行為的畸形或異常輸入樣本
DEFAULT_MALFORMED_PROBES: List[Dict[str, Any]] = [
    {"name": "malformed_json_payload", "raw_body": "{invalid_json_payload", "content_type": "application/json"},
    {"name": "oversized_field_probe", "json_body": {"input": "A" * 4096}, "content_type": "application/json"},
]

LEAK_INDICATORS: List[str] = [
    "traceback (most recent call last)",
    "werkzeug.exceptions",
    "stack trace",
    "exception at ",
    "sqlstate",
]


@dataclass
class InspectionFinding:
    module_name: str
    owasp_2025_id: str
    cwe_id: str
    target: str
    status: str  # "Vulnerable" | "Secure" | "Error"
    confidence: str  # "Heuristic" | "Direct"
    summary: str
    elapsed_ms: float
    evidence: Dict[str, Any]


class PySecHybridInspectorV2:
    """
    Three-in-One Hybrid Inspection Engine:
    [Tool 1] Passive Header Auditor (A02:2025 / CWE-693)
    [Tool 2] Active SQLi Prober (A05:2025 / CWE-89)
    [Tool 3] Fail-Closed & Exception Resilience Checker (A10:2025 / CWE-755)
    """

    def __init__(
        self,
        target_url: str,
        timeout: float = 5.0,
        required_headers: Optional[List[str]] = None,
        verify_tls: bool = True,
    ) -> None:
        self.base_url = target_url.rstrip("/")
        self.timeout = timeout
        self.required_headers = required_headers or DEFAULT_REQUIRED_HEADERS
        self.session = requests.Session()
        self.session.verify = verify_tls
        self.session.headers.update(
            {
                "User-Agent": "PySec-Hybrid-Inspector-V2/2.0 (CTIHE-03CIT4067-Lab)",
                "Accept": "application/json, text/html, */*",
            }
        )

    # [Tool 1] 被動標頭檢查器（Passive Header Auditor）
    def tool1_passive_header_audit(self, path: str = "/") -> InspectionFinding:
        url = urljoin(f"{self.base_url}/", path.lstrip("/"))
        start = time.perf_counter()
        try:
            res = self.session.get(url, timeout=self.timeout)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            headers_lower = {k.lower(): v for k, v in res.headers.items()}

            missing = [
                h for h in self.required_headers if h.lower() not in headers_lower
            ]
            acao = headers_lower.get("access-control-allow-origin", "")
            has_wildcard_cors = acao.strip() == "*"

            is_vuln = bool(missing) or has_wildcard_cors
            status = "Vulnerable" if is_vuln else "Secure"

            details: List[str] = []
            if missing:
                details.append(f"missing_headers={missing}")
            if has_wildcard_cors:
                details.append("wildcard_cors=ACAO:*")
            if not details:
                details.append("all_required_headers_and_cors_ok")

            return InspectionFinding(
                module_name="tool1_passive_header_audit",
                owasp_2025_id="A02:2025",
                cwe_id="CWE-693",
                target=url,
                status=status,
                confidence="Direct",
                summary="; ".join(details),
                elapsed_ms=elapsed_ms,
                evidence={
                    "http_status": res.status_code,
                    "missing_headers": missing,
                    "wildcard_cors": has_wildcard_cors,
                },
            )
        except requests.exceptions.RequestException as exc:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            return InspectionFinding(
                module_name="tool1_passive_header_audit",
                owasp_2025_id="A02:2025",
                cwe_id="CWE-693",
                target=url,
                status="Error",
                confidence="Direct",
                summary=f"Request failed ({type(exc).__name__})",
                elapsed_ms=elapsed_ms,
                evidence={"error_type": type(exc).__name__},
            )

    # [Tool 2] 主動 SQL 注入探測器（Active SQLi Prober）
    def tool2_active_sqli_probe(
        self,
        endpoint: str = "/rest/user/login",
        payloads: Optional[List[str]] = None,
        email_field: str = "email",
        password_field: str = "password",
    ) -> List[InspectionFinding]:
        url = urljoin(f"{self.base_url}/", endpoint.lstrip("/"))
        vectors = payloads or DEFAULT_SQLI_PAYLOADS
        findings: List[InspectionFinding] = []

        for payload in vectors:
            start = time.perf_counter()
            req_body = {email_field: payload, password_field: "lab_test_dummy"}
            try:
                res = self.session.post(url, json=req_body, timeout=self.timeout)
                elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
                text = res.text or ""

                matched_sql = [
                    sig for sig in SQL_ERROR_INDICATORS if sig.lower() in text.lower()
                ]
                is_server_5xx = res.status_code >= 500
                is_vuln = bool(matched_sql) or is_server_5xx

                status = "Vulnerable" if is_vuln else "Secure"
                summary = (
                    f"SQLi indicator/5xx observed (HTTP {res.status_code}, matches={matched_sql})"
                    if is_vuln
                    else f"No SQL error or 5xx response (HTTP {res.status_code})"
                )
                findings.append(
                    InspectionFinding(
                        module_name="tool2_active_sqli_probe",
                        owasp_2025_id="A05:2025",
                        cwe_id="CWE-89",
                        target=url,
                        status=status,
                        confidence="Heuristic",
                        summary=summary,
                        elapsed_ms=elapsed_ms,
                        evidence={
                            "http_status": res.status_code,
                            "payload": payload,
                            "matched_sql_indicators": matched_sql,
                        },
                    )
                )
            except requests.exceptions.RequestException as exc:
                elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
                findings.append(
                    InspectionFinding(
                        module_name="tool2_active_sqli_probe",
                        owasp_2025_id="A05:2025",
                        cwe_id="CWE-89",
                        target=url,
                        status="Error",
                        confidence="Heuristic",
                        summary=f"Probe request error ({type(exc).__name__})",
                        elapsed_ms=elapsed_ms,
                        evidence={
                            "payload": payload,
                            "error_type": type(exc).__name__,
                        },
                    )
                )
        return findings

    # [Tool 3] 例外處理與 Fail-Closed 韌性探測器（Exception & Fail-Closed Checker）
    def tool3_fail_closed_resilience_check(
        self,
        endpoint: str = "/api/protected",
        probes: Optional[List[Dict[str, Any]]] = None,
    ) -> List[InspectionFinding]:
        url = urljoin(f"{self.base_url}/", endpoint.lstrip("/"))
        cases = probes or DEFAULT_MALFORMED_PROBES
        findings: List[InspectionFinding] = []

        for case in cases:
            start = time.perf_counter()
            case_name = case.get("name", "unnamed_probe")
            headers = {"Content-Type": case.get("content_type", "application/json")}
            data_arg = (
                case["raw_body"]
                if "raw_body" in case
                else json.dumps(case.get("json_body", {}))
            )

            try:
                res = self.session.post(
                    url, data=data_arg, headers=headers, timeout=self.timeout
                )
                elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
                body = res.text or ""

                leaked_traces = [
                    tok for tok in LEAK_INDICATORS if tok in body.lower()
                ]
                # 若在異常輸入下回傳 200 OK 且無阻斷提示，視為潛在 Fail-Open 風險；
                # 正常防禦下應為 400 / 401 / 403 / 503 且不洩漏 Traceback
                unexpected_200 = res.status_code == 200
                is_vuln = bool(leaked_traces) or unexpected_200

                status = "Vulnerable" if is_vuln else "Secure"
                summary = (
                    f"Potential fail-open/leakage (HTTP {res.status_code}, leaks={leaked_traces})"
                    if is_vuln
                    else f"Controlled error/denial response without trace leak (HTTP {res.status_code})"
                )
                findings.append(
                    InspectionFinding(
                        module_name="tool3_fail_closed_resilience_check",
                        owasp_2025_id="A10:2025",
                        cwe_id="CWE-755",
                        target=url,
                        status=status,
                        confidence="Heuristic",
                        summary=summary,
                        elapsed_ms=elapsed_ms,
                        evidence={
                            "probe_name": case_name,
                            "http_status": res.status_code,
                            "leaked_trace_tokens": leaked_traces,
                        },
                    )
                )
            except requests.exceptions.RequestException as exc:
                elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
                findings.append(
                    InspectionFinding(
                        module_name="tool3_fail_closed_resilience_check",
                        owasp_2025_id="A10:2025",
                        cwe_id="CWE-755",
                        target=url,
                        status="Error",
                        confidence="Heuristic",
                        summary=f"Resilience probe error ({type(exc).__name__})",
                        elapsed_ms=elapsed_ms,
                        evidence={
                            "probe_name": case_name,
                            "error_type": type(exc).__name__,
                        },
                    )
                )
        return findings

    def run_all(
        self,
        header_path: str = "/",
        sqli_endpoint: str = "/rest/user/login",
        resilience_endpoint: str = "/api/protected",
    ) -> Dict[str, Any]:
        started_at = datetime.now(timezone.utc).isoformat()
        f1 = self.tool1_passive_header_audit(path=header_path)
        f2_list = self.tool2_active_sqli_probe(endpoint=sqli_endpoint)
        f3_list = self.tool3_fail_closed_resilience_check(endpoint=resilience_endpoint)

        combined: List[InspectionFinding] = [f1, *f2_list, *f3_list]
        total_ms = round(sum(item.elapsed_ms for item in combined), 2)

        return {
            "tool": "PySec-Hybrid Inspector V2 (3-in-1)",
            "target_base_url": self.base_url,
            "timestamp_utc": started_at,
            "metrics": {
                "total_findings": len(combined),
                "vulnerable_count": sum(1 for x in combined if x.status == "Vulnerable"),
                "secure_count": sum(1 for x in combined if x.status == "Secure"),
                "error_count": sum(1 for x in combined if x.status == "Error"),
                "total_elapsed_ms": total_ms,
            },
            "findings": [asdict(x) for x in combined],
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PySec-Hybrid Inspector V2 (3-in-1 Web Security Checker)"
    )
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--header-path", default="/")
    parser.add_argument("--sqli-endpoint", default="/rest/user/login")
    parser.add_argument("--resilience-endpoint", default="/api/protected")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--output-json", default="")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    engine = PySecHybridInspectorV2(target_url=args.target, timeout=args.timeout)
    report = engine.run_all(
        header_path=args.header_path,
        sqli_endpoint=args.sqli_endpoint,
        resilience_endpoint=args.resilience_endpoint,
    )
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    print(rendered)
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            f.write(rendered + "\n")
        logger.info("Saved report to %s", args.output_json)


if __name__ == "__main__":
    main()