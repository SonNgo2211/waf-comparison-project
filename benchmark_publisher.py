"""Publish independently labeled WCP results to the WAF training server."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.request
from pathlib import Path
from typing import Any

RESULTS_PATH = Path(os.getenv("WCP_RESULTS_PATH", "results"))
DB_PATH = RESULTS_PATH / "db"
DB_FILE_NAME = "waf_comparison.duckdb"
DB_TABLE_NAME = "waf_comparison"
log = logging.getLogger("wcp.benchmark_publisher")


ATTACK_CATEGORY_MAP = {
    "xss": "xss",
    "cross_site_scripting": "xss",
    "sqli": "sqli",
    "sql_injection": "sqli",
    "traversal": "path_traversal",
    "path_traversal": "path_traversal",
    "lfi": "path_traversal",
    "cmdexe": "rce",
    "command_injection": "rce",
    "shellshock": "rce",
    "log4shell": "rce",
    "rce": "rce",
    "xxe": "xxe",
}


def _json_get(url: str, timeout: float = 10.0, max_retries: int = 5) -> dict[str, Any]:
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                value = json.loads(response.read().decode("utf-8"))
            return value if isinstance(value, dict) else {}
        except TimeoutError:
            if attempt == max_retries - 1:
                raise
            import time
            time.sleep(1.0)
    return {}


def prepare_benchmark_session() -> dict[str, Any]:
    """Ask the training server to authorize and prepare one benchmark run."""
    training_url = os.getenv("TRAINING_SERVER_URL", "http://waf-training:8081").rstrip("/")
    headers = {"Content-Type": "application/json"}
    token = os.getenv("TRAINING_API_TOKEN", "")
    if token:
        headers["X-WAF-Token"] = token
    request = urllib.request.Request(
        f"{training_url}/api/v1/benchmark/sessions",
        data=json.dumps({
            "namespace": os.getenv("WCP_NAMESPACE", "default"),
            "app": os.getenv("WCP_APP", "dvwa"),
            "ttl_seconds": int(os.getenv("WCP_BENCHMARK_SESSION_TTL", "14400")),
        }).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30.0) as response:
        result = json.loads(response.read().decode("utf-8"))
    session = result.get("session") if isinstance(result, dict) else None
    if not isinstance(session, dict) or not session.get("session_id"):
        raise RuntimeError("training server did not prepare a benchmark session")
    identity = session.get("identity") if isinstance(session.get("identity"), dict) else {}
    if not identity.get("model_version"):
        raise RuntimeError("benchmark session has no active model identity")
    log.info(
        "Prepared server-owned benchmark session: id=%s primary=%s shadow=%s",
        str(session["session_id"])[:12],
        identity.get("model_version", ""),
        session.get("candidate_version", ""),
    )
    return session


def _json_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def capture_runtime_identity() -> dict[str, Any]:
    agent_url = os.getenv("AI_AGENT_URL", "http://waf-ai-agent:8080").rstrip("/")
    agent = _json_get(f"{agent_url}/health")
    runtime = agent.get("runtime_bundle") if isinstance(agent.get("runtime_bundle"), dict) else {}
    active_versions = runtime.get("active_versions") if isinstance(runtime.get("active_versions"), dict) else {}
    runtime_policy = {
        "runtime_calibration": agent.get("runtime_calibration") or {},
        "waap_policy": agent.get("waap_policy") or {},
    }
    return {
        "model_version": str(active_versions.get("primary") or agent.get("model_version") or ""),
        "active_bundle_id": str(runtime.get("active_bundle_id") or ""),
        "runtime_content_id": str(runtime.get("active_content_id") or runtime.get("active_bundle_id") or ""),
        "semantic_model_version": str(active_versions.get("semantic") or ""),
        "runtime_policy_sha256": _json_digest(runtime_policy),
        "namespace": str(agent.get("namespace") or os.getenv("WCP_NAMESPACE", "default")),
        "app": str(agent.get("app_scope") or os.getenv("WCP_APP", "dvwa")),
        "captured_at": time.time(),
    }


def runtime_identity_matches(start: dict[str, Any], end: dict[str, Any]) -> bool:
    return bool(start.get("model_version")) and all(
        str(start.get(key) or "") == str(end.get(key) or "")
        for key in (
            "model_version",
            "runtime_content_id",
            "semantic_model_version",
            "runtime_policy_sha256",
        )
    )


def normalize_attack_category(value: object) -> str:
    name = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return ATTACK_CATEGORY_MAP.get(name, name)[:64]


def build_evaluation_payload(
    *,
    identity: dict[str, Any],
    waf_name: str,
    db_sha256: str,
    counts: dict[str, int],
    category_rows: list[tuple[str, int, int]],
    latency: dict[str, float],
    evaluated_at: float,
) -> dict[str, Any]:
    attacks: dict[str, dict[str, int]] = {}
    for raw_category, tp, fn in category_rows:
        category = normalize_attack_category(raw_category)
        if not category:
            continue
        current = attacks.setdefault(category, {"tp": 0, "fn": 0})
        current["tp"] += int(tp or 0)
        current["fn"] += int(fn or 0)
    source_identity = {
        "db_sha256": db_sha256,
        "waf_name": waf_name,
        "model_version": identity["model_version"],
        "active_bundle_id": identity.get("active_bundle_id", ""),
        "runtime_content_id": identity.get("runtime_content_id", ""),
        "semantic_model_version": identity.get("semantic_model_version", ""),
        "runtime_policy_sha256": identity.get("runtime_policy_sha256", ""),
        "benchmark_session_id": identity.get("benchmark_session_id", ""),
    }
    source_id = hashlib.sha256(
        json.dumps(source_identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "benchmark_session_id": identity.get("benchmark_session_id") or "",
        "model_version": identity["model_version"],
        "namespace": identity.get("namespace") or "global",
        "app": identity.get("app") or "",
        "source": "openappsec-waf-comparison-project",
        "source_id": source_id,
        "independent_labels": True,
        "label_provenance": "benchmark_dataset",
        "evaluated_at": evaluated_at,
        "counts": counts,
        "attack_types": attacks,
        "latency": latency,
        "metadata": {
            "benchmark_session_id": identity.get("benchmark_session_id") or "",
            "candidate_version": identity.get("candidate_version") or "",
            "waf_name": waf_name,
            "database_sha256": db_sha256,
            "active_bundle_id": identity.get("active_bundle_id") or "",
            "runtime_content_id": identity.get("runtime_content_id") or "",
            "semantic_model_version": identity.get("semantic_model_version") or "",
            "runtime_policy_sha256": identity.get("runtime_policy_sha256") or "",
        },
    }


def read_wcp_evaluation(identity: dict[str, Any], waf_name: str) -> dict[str, Any]:
    import duckdb

    db_path = Path(DB_PATH) / DB_FILE_NAME
    digest = hashlib.sha256(db_path.read_bytes()).hexdigest()
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        quoted_table = '"' + DB_TABLE_NAME.replace('"', '""') + '"'
        row = conn.execute(
            f"""SELECT
                count(*) FILTER (WHERE \"DataSetType\"='Malicious' AND \"isBlocked\"=1) AS tp,
                count(*) FILTER (WHERE \"DataSetType\"='Legitimate' AND \"isBlocked\"=1) AS fp,
                count(*) FILTER (WHERE \"DataSetType\"='Legitimate' AND \"isBlocked\"=0) AS tn,
                count(*) FILTER (WHERE \"DataSetType\"='Malicious' AND \"isBlocked\"=0) AS fn,
                quantile_cont(response_time_ms, 0.95) AS p95_ms,
                quantile_cont(response_time_ms, 0.99) AS p99_ms
                FROM {quoted_table} WHERE response_status_code != 0 AND \"WAF_Name\"=?""",
            [waf_name],
        ).fetchone()
        categories = conn.execute(
            f"""SELECT coalesce(\"Category\", \"TestName\") AS category,
                count(*) FILTER (WHERE \"isBlocked\"=1) AS tp,
                count(*) FILTER (WHERE \"isBlocked\"=0) AS fn
                FROM {quoted_table}
                WHERE response_status_code != 0 AND \"DataSetType\"='Malicious' AND \"WAF_Name\"=?
                GROUP BY coalesce(\"Category\", \"TestName\")
                ORDER BY category""",
            [waf_name],
        ).fetchall()
    finally:
        conn.close()
    if not row or sum(int(value or 0) for value in row[:4]) == 0:
        raise ValueError(f"no completed benchmark rows for WAF {waf_name!r}")
    return build_evaluation_payload(
        identity=identity,
        waf_name=waf_name,
        db_sha256=digest,
        counts={"tp": int(row[0]), "fp": int(row[1]), "tn": int(row[2]), "fn": int(row[3])},
        category_rows=categories,
        latency={"p95_ms": float(row[4] or 0.0), "p99_ms": float(row[5] or 0.0)},
        evaluated_at=db_path.stat().st_mtime,
    )


def publish_benchmark(start_identity: dict[str, Any]) -> bool:
    if os.getenv("WCP_PUBLISH_BENCHMARK", "false").lower() not in {"1", "true", "yes", "on"}:
        return False
    try:
        end_identity = capture_runtime_identity()
        if not runtime_identity_matches(start_identity, end_identity):
            log.error("Runtime model/content changed during execution; refusing to publish mixed benchmark evidence")
            return False
        waf_name = os.getenv("WCP_WAF_NAME", "Whackers NginxWAF")
        payload = read_wcp_evaluation(start_identity, waf_name)
        training_url = os.getenv("TRAINING_SERVER_URL", "http://waf-training:8081").rstrip("/")
        request = urllib.request.Request(
            f"{training_url}/api/v1/benchmark/evaluations",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", **(
                {"X-WAF-Token": os.environ["TRAINING_API_TOKEN"]}
                if os.getenv("TRAINING_API_TOKEN") else {}
            )},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=15.0) as response:
            result = json.loads(response.read().decode("utf-8"))
        gate = result.get("quality_gate") if isinstance(result, dict) else {}
        log.info("Published benchmark evidence: report=%s gate_passed=%s", payload["source_id"], gate.get("passed"))
        return True
    except Exception:
        log.exception("Benchmark report was generated but evidence publication failed")
        return False
