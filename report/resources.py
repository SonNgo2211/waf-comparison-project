"""Resource usage page: what the run cost the WAF, next to what it blocked.

The numbers are NOT collected here. This container is the load generator and
sits on the WAF's network with no view of the host: per-container cgroup
counters and per-process /proc entries (each agent worker, the nginx workers)
live on the host, and reading them from inside would take the docker socket
and the host pid namespace -- root on the host -- while competing for the CPU
being measured. DVWA/bench_monitor.py samples them from the host during the
run and writes report.json; this module only renders it.

Which report: $WCP_RESOURCE_REPORT, which DVWA/run_wcp_measured.sh sets when it
regenerates the PDF after the run. Unset -> no resource pages, report unchanged.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from logger import log


def _find_report() -> Optional[Path]:
    # Explicit only. A "newest report whose window covers the DB" fallback was
    # tried and attached the wrong run: DuckDB rewrites the file's mtime when it
    # is opened, so the window test matches whatever ran last. And at the end of
    # a fresh run there is nothing to find yet -- the monitor finishes after WCP.
    explicit = os.getenv("WCP_RESOURCE_REPORT", "").strip()
    if not explicit:
        return None
    path = Path(explicit)
    if path.is_file():
        return path
    log.warning(f"WCP_RESOURCE_REPORT={explicit} does not exist; resource page skipped")
    return None


def _f(value: Any, fmt: str = "{:.1f}", suffix: str = "") -> str:
    if value is None:
        return "-"
    try:
        return fmt.format(value) + suffix
    except (TypeError, ValueError):
        return str(value)


def _client_latency_from_db() -> Dict[str, Dict[str, Any]]:
    """Client-side latency of every request in THIS run's database (the run
    being reported), by dataset and outcome; status 0 (never answered) excluded."""
    try:
        from sqlalchemy import text
        from config import conn, DB_TABLE_NAME
        with conn.connect() as c:
            rows = c.execute(text(
                f'SELECT "DataSetType", "isBlocked", count(*), quantile_cont(response_time_ms, 0.5), '
                f'quantile_cont(response_time_ms, 0.95), quantile_cont(response_time_ms, 0.99), '
                f'max(response_time_ms) FROM "{DB_TABLE_NAME}" WHERE response_status_code != 0 GROUP BY 1, 2'
            )).fetchall()
    except Exception as exc:                                  # the page must never break the report
        log.warning(f"Client latency query failed ({exc}); latency table from report.json only")
        return {}
    return {f"{ds}/{'blocked' if blk else 'passed'}": {"n": n, "p50": p50, "p95": p95, "p99": p99, "max": mx}
            for ds, blk, n, p50, p95, p99, mx in rows}


def _timeouts_from_db() -> Optional[int]:
    """Requests with no answer within 2 s x 3 tries (status 0): the slowest of
    the run, and absent from every percentile (item 109)."""
    try:
        from sqlalchemy import text
        from config import conn, DB_TABLE_NAME
        with conn.connect() as c:
            return int(c.execute(text(f'SELECT count(*) FROM "{DB_TABLE_NAME}" WHERE response_status_code = 0')).scalar() or 0)
    except Exception:
        return None


def _latency_rows(rep: Dict[str, Any]) -> List[List[str]]:
    rows = []
    # Item 109: nginx's own request_time for EVERY request (access log), over
    # the load window when the monitor found one -- the server-side number,
    # not the client's, and not only the blocked requests.
    server = ((rep.get("load_window") or {}).get("server_latency") or rep.get("server_latency") or {})
    for key, label in (("all", "server, every request"), ("waf_added", "server, WAF-added (request - upstream)")):
        d = server.get(key) or {}
        if d.get("n"):
            rows.append([label, str(d.get("n")), _f(d.get("p50")), _f(d.get("p95")), _f(d.get("p99")), _f(d.get("max"))])
    latency = _client_latency_from_db() or (rep.get("wcp") or {}).get("latency") or {}
    for key in ("Legitimate/passed", "Legitimate/blocked", "Malicious/blocked", "Malicious/passed"):
        d = latency.get(key)
        if d:
            rows.append([f"client, {key}", str(d.get("n")), _f(d.get("p50")), _f(d.get("p95")), _f(d.get("p99")), _f(d.get("max"))])
    lat = rep.get("latency_ms") or {}
    for key, label in (("waf_added (request_time - upstream)", "WAF-added, actionable"),
                       ("agent_ms (self-report)", "agent self-report, actionable")):
        d = lat.get(key) or {}
        if d.get("n"):
            rows.append([label, str(d.get("n")), _f(d.get("p50")), _f(d.get("p95")), _f(d.get("p99")), _f(d.get("max"))])
    return rows


def load_resource_context() -> Optional[Dict[str, Any]]:
    path = _find_report()
    if not path:
        return None
    try:
        rep = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        log.warning(f"Resource report {path} unreadable ({exc}); resource page skipped")
        return None
    log.info(f"Adding resource usage page from {path}")
    containers = rep.get("containers") or {}
    agent, nginx = containers.get("waf-ai-agent") or {}, containers.get("nginxwaf") or {}
    cpu = rep.get("cpu") or {}
    req = rep.get("requests") or {}
    fail_open = sum((req.get("fail_open") or {}).values())
    window = rep.get("load_window") or {}
    node = window.get("node") or rep.get("node") or {}
    timeouts = _timeouts_from_db()
    if timeouts is None:
        timeouts = (rep.get("wcp") or {}).get("unmeasured_status0")
    wl = (window.get("server_latency") or {}).get("all") or {}
    kpis = [
        ("Load window", f"{_f(window.get('duration_s'), '{:.0f}', ' s')}, {_f(window.get('rps_mean'), '{:.0f}')} req/s "
                        f"(peak {_f(window.get('rps_peak'), '{:.0f}')})"),
        ("Server latency p95 / p99", f"{_f(wl.get('p95'), '{:.0f}')} / {_f(wl.get('p99'), '{:.0f}')} ms, every request"),
        ("Node CPU busy mean / p95", f"{_f((node.get('busy_pct') or {}).get('mean'), '{:.0f}')} / "
                                     f"{_f((node.get('busy_pct') or {}).get('p95'), '{:.0f}')} % of {node.get('cpus') or '-'} CPUs"),
        ("Node CPU pressure (PSI some)", _f((node.get("psi_cpu_some_pct") or {}).get("mean"), "{:.1f}", " %")),
        ("Agent CPU throttled", _f(window.get("agent_throttled_ms_total"), "{:.0f}", " ms")),
        ("WCP timeouts (> 2 s, not in percentiles)", "-" if timeouts is None else str(timeouts)),
        ("Agent net CPU / scored request", _f(cpu.get("agent_net_cpu_ms_per_agent_request", cpu.get("agent_cpu_ms_per_agent_request")), "{:.2f}", " ms")
                                           + ("" if cpu.get("agent_requests_est") else " (not computable: workers restarted)")),
        ("NGINX net CPU / request", _f(cpu.get("nginx_net_cpu_ms_per_request", cpu.get("nginx_cpu_ms_per_request")), "{:.2f}", " ms")),
        ("Agent cores p95 / limit", f"{_f(agent.get('cores_p95'), '{:.2f}')} / {_f(agent.get('cpu_limit'), '{:.0f}')}"),
        ("Agent RSS max / limit", f"{_f(agent.get('rss_mb_max'), '{:.0f}')} / {_f(agent.get('mem_limit_mb'), '{:.0f}')} MB"),
        ("NGINX cores p95", _f(nginx.get("cores_p95"), "{:.2f}")),
        ("NGINX RSS max", _f(nginx.get("rss_mb_max"), "{:.0f}", " MB")),
        ("Fail-open (no verdict, allowed)", f"{fail_open} = {_f((req.get('fail_open_rate') or 0) * 100, '{:.2f}')} % of all requests, "
                                            f"{_f((req.get('fail_open_share_of_verdict_path') or 0) * 100, '{:.1f}')} % of those needing a verdict"),
        ("Fail-open inside agent stall windows", f"{req.get('fail_open_in_stalls', '-')} in {len(req.get('stall_windows') or [])} window(s); "
                                                 f"{req.get('fail_open_outside_stalls', '-')} outside"),
        ("Agent-path latency p95, outside stalls", _f((((rep.get('latency_outside_stalls_ms') or {}).get('ai_path')) or {}).get('p95'), "{:.0f}", " ms")),
        ("FP among SCORED legit (WCP)", _f(((rep.get("wcp") or {}).get("fp_rate_scored") or 0) * 100 if (rep.get("wcp") or {}).get("fp_rate_scored") is not None else None, "{:.3f}", " %")),
        ("Malicious let through unscored (WCP)", str((rep.get("wcp") or {}).get("malicious_unscored_passed", "-"))),
        ("No verdict, fast-rule fallback enforced", str(sum((req.get("ai_down_fallback") or {}).values()))),
        ("Agent event-loop lag p95", _f((rep.get("agent_loop_lag_ms") or {}).get("p95"), "{:.1f}", " ms")),
    ]
    container_rows = [
        [name + (" (restarted)" if c.get("RESTARTED") else ""), _f(c.get("cpu_s")), _f(c.get("cores_mean"), "{:.2f}"),
         _f(c.get("cores_p95"), "{:.2f}"), _f(c.get("cores_max"), "{:.2f}"), _f(c.get("cpu_limit"), "{:.0f}"),
         _f(c.get("throttled_s"), "{:.2f}"), _f(c.get("rss_mb_max"), "{:.0f}"), _f(c.get("mem_limit_mb"), "{:.0f}")]
        for name, c in sorted(containers.items(), key=lambda kv: -(kv[1].get("cpu_s") or 0))
    ]
    worker_rows = [
        [pid, _f(w.get("cpu_s")), _f(w.get("cores_mean"), "{:.2f}"), _f(w.get("rss_mb_start"), "{:.0f}"),
         _f(w.get("rss_mb_max"), "{:.0f}"), _f(w.get("rss_growth_mb"), "{:+.0f}")]
        for pid, w in sorted((rep.get("agent_workers") or {}).items())
    ]
    stage_rows = [
        [stage, str(s.get("count")), _f(s.get("mean_ms"), "{:.2f}"), _f(s.get("p50_ms"), "{:.2f}"),
         _f(s.get("p95_ms"), "{:.2f}"), _f(s.get("p99_ms"), "{:.2f}")]
        for stage, s in sorted((rep.get("agent_stages") or {}).items(),
                               key=lambda kv: -(kv[1].get("mean_ms") or 0) * (kv[1].get("count") or 0))
    ]
    scraped = rep.get("agent_workers_scraped") or {}
    return {
        "label": rep.get("label"),
        "window": f"{time.strftime('%Y-%m-%d %H:%M', time.gmtime(rep.get('t0') or 0))} UTC, "
                  f"{_f(rep.get('duration_s'), '{:.0f}', ' s')}",
        "model": rep.get("agent_model") or "-",
        "images": ", ".join(f"{k}: {str(v).split(':')[-1]}" for k, v in (rep.get("images") or {}).items()
                            if k in ("nginxwaf", "waf-ai-agent", "waf-training")),
        "kpis": kpis,
        "containers": container_rows,
        "workers": worker_rows,
        "stages": stage_rows,
        "stages_note": f"{scraped.get('end', 0)} of {rep.get('agent_workers_n') or '-'} agent workers answered "
                       "the metrics scrape; counts are theirs, timings are a sample of all.",
        "latency": _latency_rows(rep),
        "source": str(path),
    }
