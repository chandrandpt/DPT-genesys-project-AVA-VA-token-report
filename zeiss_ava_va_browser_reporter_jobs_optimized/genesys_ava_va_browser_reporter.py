#!/usr/bin/env python3
"""Genesys Cloud AVA/VA Division Reporter - local browser app.

Standard-library only. Starts an HTTP server bound to 127.0.0.1 and opens the
user's browser. OAuth credentials are held in memory only and are sent only to
the configured Genesys Cloud login endpoint.
"""

from __future__ import annotations

import base64
import csv
import datetime as dt
import io
import json
import os
import hashlib
import ssl
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo

APP_NAME = "Genesys AVA/VA Division Reporter - Jobs Optimized"
DEFAULT_API_BASE = "https://api.mypurecloud.de"
DEFAULT_TZ = "Europe/Berlin"
FLOW_PAGE_SIZE = 100
JOB_RESULT_PAGE_SIZE = 10000
JOB_FLOW_BATCH_SIZE = 150
JOB_POLL_INITIAL_SECONDS = 8.0
JOB_POLL_MAX_SECONDS = 30.0
JOB_TIMEOUT_SECONDS = 900
FLOW_CACHE_TTL_SECONDS = 6 * 3600
DIVISION_CACHE_TTL_SECONDS = 24 * 3600
MAX_HTTP_RETRIES = 5

STATE_LOCK = threading.Lock()
STATE = {
    "flow_rows": [],
    "target_flows": {},
    "divisions": {},
    "interaction_rows": [],
    "conversation_rows": [],
    "summary_rows": [],
    "version_rows": [],
    "last_scan_summary": {},
    "last_report_summary": {},
    "version_cache": {},
}
_SSL_CONTEXTS = {}
_TOKEN_CACHE = {}
_TOKEN_CACHE_LOCK = threading.Lock()
CACHE_DIR = os.path.expanduser("~/.genesys_ava_va_reporter")
CACHE_FILE = os.path.join(CACHE_DIR, "metadata_cache_v4.json")

class ApiMetrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.counts = defaultdict(int)
    def record(self, name):
        with self.lock:
            self.counts[name or "other"] += 1
    def snapshot(self):
        with self.lock:
            return dict(self.counts)
    @staticmethod
    def diff(before, after):
        keys = set(before) | set(after)
        return {k: after.get(k, 0) - before.get(k, 0) for k in sorted(keys) if after.get(k, 0) - before.get(k, 0)}

API_METRICS = ApiMetrics()

def tenant_cache_key(api_base, client_id):
    raw = (api_base.rstrip("/") + "|" + client_id).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]

def load_disk_cache():
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def save_disk_cache(data):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        tmp = CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, CACHE_FILE)
    except Exception:
        pass

def get_tenant_disk_cache(api_base, client_id):
    root = load_disk_cache()
    key = tenant_cache_key(api_base, client_id)
    tenant = root.get(key)
    return root, key, tenant if isinstance(tenant, dict) else {}


def html_escape(value):
    s = str(value if value is not None else "")
    return (s.replace("&", "&amp;").replace("<", "&lt;")
              .replace(">", "&gt;").replace('"', "&quot;")
              .replace("'", "&#39;"))


def json_bytes(obj, status=200):
    return status, "application/json; charset=utf-8", json.dumps(obj, ensure_ascii=False).encode("utf-8")


def get_ssl_context(extra_ca_path=""):
    key = os.path.abspath(os.path.expanduser(extra_ca_path.strip())) if extra_ca_path.strip() else "__default__"
    if key in _SSL_CONTEXTS:
        return _SSL_CONTEXTS[key]

    ctx = ssl.create_default_context()

    # Managed Macs often trust a corporate TLS inspection CA in Keychain while
    # Python/OpenSSL does not. Import those trusted certificates without
    # disabling verification.
    if sys.platform == "darwin":
        keychains = [
            "/System/Library/Keychains/SystemRootCertificates.keychain",
            "/Library/Keychains/System.keychain",
            os.path.expanduser("~/Library/Keychains/login.keychain-db"),
        ]
        pem_parts = []
        for keychain in keychains:
            if not os.path.exists(keychain):
                continue
            try:
                proc = subprocess.run(
                    ["security", "find-certificate", "-a", "-p", keychain],
                    capture_output=True, text=True, check=False, timeout=30,
                )
                if proc.returncode == 0 and "BEGIN CERTIFICATE" in proc.stdout:
                    pem_parts.append(proc.stdout)
            except Exception:
                pass
        if pem_parts:
            bundle = os.path.expanduser("~/.genesys_ava_va_macos_ca.pem")
            try:
                with open(bundle, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(pem_parts))
                ctx.load_verify_locations(cafile=bundle)
            except Exception:
                pass

    if extra_ca_path.strip():
        path = os.path.abspath(os.path.expanduser(extra_ca_path.strip()))
        if not os.path.isfile(path):
            raise ValueError(f"Corporate CA PEM file not found: {path}")
        ctx.load_verify_locations(cafile=path)

    _SSL_CONTEXTS[key] = ctx
    return ctx


def api_error_text(exc):
    if isinstance(exc, urllib.error.HTTPError):
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return f"HTTP {exc.code}: {body or exc.reason}"
    if isinstance(exc, urllib.error.URLError):
        return f"Network error: {exc.reason}"
    return str(exc)


def http_json(method, url, token=None, body=None, form=None, basic_auth=None,
              timeout=90, ca_path="", metric_name=""):
    headers = {"Accept": "application/json", "User-Agent": "Zeiss-AVA-VA-Reporter/4.0-Jobs"}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if basic_auth:
        raw = f"{basic_auth[0]}:{basic_auth[1]}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    last_exc = None
    for attempt in range(MAX_HTTP_RETRIES):
        API_METRICS.record(metric_name or "other")
        if attempt:
            API_METRICS.record("http_retry_attempts")
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=get_ssl_context(ca_path)) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            last_exc = exc
            if exc.code in (429, 500, 502, 503, 504) and attempt < MAX_HTTP_RETRIES - 1:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    wait = float(retry_after) if retry_after else min(2 ** attempt, 10)
                except Exception:
                    wait = min(2 ** attempt, 10)
                time.sleep(wait)
                continue
            raise
        except urllib.error.URLError as exc:
            last_exc = exc
            if attempt < MAX_HTTP_RETRIES - 1:
                time.sleep(min(2 ** attempt, 8))
                continue
            raise
    if last_exc:
        raise last_exc
    raise RuntimeError("HTTP request failed")


def login_base_from_api(api_base):
    parsed = urllib.parse.urlparse(api_base.strip().rstrip("/"))
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("API base must look like https://api.mypurecloud.de")
    host = parsed.netloc
    if not host.startswith("api."):
        raise ValueError("Genesys API hostname must start with api.")
    return f"https://login.{host[4:]}"


def get_oauth_token(api_base, client_id, client_secret, ca_path=""):
    if not client_id or not client_secret:
        raise ValueError("Client ID and Client Secret are required.")
    cache_key = (api_base.rstrip("/"), client_id, ca_path or "")
    now = time.time()
    with _TOKEN_CACHE_LOCK:
        cached = _TOKEN_CACHE.get(cache_key)
        if cached and cached.get("expires_at", 0) > now + 60:
            return cached["token"]
    result = http_json(
        "POST",
        login_base_from_api(api_base) + "/oauth/token",
        form={"grant_type": "client_credentials"},
        basic_auth=(client_id, client_secret),
        timeout=45,
        ca_path=ca_path,
        metric_name="oauth_token",
    )
    token = result.get("access_token")
    if not token:
        raise RuntimeError("OAuth response did not contain access_token.")
    expires_in = int(result.get("expires_in") or 3600)
    with _TOKEN_CACHE_LOCK:
        _TOKEN_CACHE[cache_key] = {"token": token, "expires_at": now + expires_in}
    return token


def extract_entities(data):
    for key in ("entities", "flows", "results"):
        value = data.get(key)
        if isinstance(value, list):
            return value
    return []


def get_all_flows(api_base, token, ca_path=""):
    api_base = api_base.rstrip("/")
    flows = []
    page = 1
    while True:
        params = urllib.parse.urlencode({"pageSize": FLOW_PAGE_SIZE, "pageNumber": page})
        data = http_json("GET", f"{api_base}/api/v2/flows?{params}", token=token, ca_path=ca_path, metric_name="flows_list")
        entities = extract_entities(data)
        flows.extend(entities)
        page_count = data.get("pageCount") or data.get("page_count")
        if page_count is not None:
            try:
                if page >= int(page_count):
                    break
            except Exception:
                pass
        if len(entities) < FLOW_PAGE_SIZE:
            break
        page += 1
        if page > 10000:
            raise RuntimeError("Flow pagination safety limit reached.")
    # Deduplicate just in case.
    return list({f.get("id"): f for f in flows if f.get("id")}.values())


def get_flow_detail(api_base, token, flow_id, ca_path=""):
    url = f"{api_base.rstrip('/')}/api/v2/flows/{urllib.parse.quote(flow_id)}"
    return http_json("GET", url, token=token, ca_path=ca_path, metric_name="flow_detail")


def has_capability_fields(flow):
    for container in (flow, flow.get("publishedVersion") or {}, flow.get("checkedInVersion") or {}, flow.get("savedVersion") or {}):
        if "virtualAgentEnabled" in container or "agenticVirtualAgentEnabled" in container:
            return True
    return False


def enrich_all_flows(api_base, token, listed_flows, ca_path=""):
    # Optimization: current GET /flows responses can already include the VA/AVA
    # capability flags. Only make a per-flow detail call when those fields are
    # actually absent from the list response.
    results = {f["id"]: f for f in listed_flows if f.get("id") and has_capability_fields(f)}
    bot_types = {"BOT", "DIGITALBOT"}
    missing = [f for f in listed_flows if f.get("id") and not has_capability_fields(f) and str(f.get("type") or "").upper() in bot_types]
    for f in listed_flows:
        if f.get("id") and f.get("id") not in results and f not in missing:
            results[f["id"]] = f
    errors = {}
    if not missing:
        return results, errors, 0
    max_workers = min(6, max(1, len(missing)))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(get_flow_detail, api_base, token, f["id"], ca_path): f["id"]
            for f in missing
        }
        for future in as_completed(futures):
            fid = futures[future]
            try:
                results[fid] = future.result()
            except Exception as exc:
                errors[fid] = api_error_text(exc)
                original = next((f for f in missing if f.get("id") == fid), None)
                if original:
                    results[fid] = original
    return results, errors, len(missing)


def bool_field(flow, name):
    if name in flow:
        return bool(flow.get(name))
    pub = flow.get("publishedVersion") or {}
    if name in pub:
        return bool(pub.get(name))
    checked = flow.get("checkedInVersion") or {}
    if name in checked:
        return bool(checked.get(name))
    saved = flow.get("savedVersion") or {}
    return bool(saved.get(name)) if name in saved else False


def flow_capability(va_enabled, ava_enabled):
    if va_enabled and ava_enabled:
        return "VA + AVA enabled"
    if ava_enabled:
        return "AVA enabled"
    if va_enabled:
        return "VA enabled"
    return "Neither"


def flow_to_row(flow, detail_error=""):
    division = flow.get("division") or {}
    pub = flow.get("publishedVersion") or {}
    va = bool_field(flow, "virtualAgentEnabled")
    ava = bool_field(flow, "agenticVirtualAgentEnabled")
    return {
        "flow_id": flow.get("id", ""),
        "flow_name": flow.get("name", ""),
        "flow_type": flow.get("type", ""),
        "active": flow.get("active", ""),
        "deleted": flow.get("deleted", ""),
        "flow_division_id": division.get("id", ""),
        "flow_division_name": division.get("name", ""),
        "virtual_agent_enabled": va,
        "agentic_virtual_agent_enabled": ava,
        "capability": flow_capability(va, ava),
        "published_version": pub.get("id", ""),
        "published_version_virtual_agent_enabled": pub.get("virtualAgentEnabled", "") if "virtualAgentEnabled" in pub else "",
        "published_version_agentic_virtual_agent_enabled": pub.get("agenticVirtualAgentEnabled", "") if "agenticVirtualAgentEnabled" in pub else "",
        "date_published": pub.get("datePublished", ""),
        "detail_error": detail_error,
    }



def get_flow_version_detail(api_base, token, flow_id, version_id, ca_path=""):
    fid = urllib.parse.quote(str(flow_id), safe="")
    vid = urllib.parse.quote(str(version_id), safe="")
    url = f"{api_base.rstrip('/')}/api/v2/flows/{fid}/versions/{vid}"
    return http_json("GET", url, token=token, ca_path=ca_path, metric_name="flow_version_detail")


def get_flow_versions_page(api_base, token, flow_id, page_number=1, page_size=100, ca_path=""):
    fid = urllib.parse.quote(str(flow_id), safe="")
    params = urllib.parse.urlencode({"pageNumber": page_number, "pageSize": page_size, "deleted": "false"})
    url = f"{api_base.rstrip('/')}/api/v2/flows/{fid}/versions?{params}"
    return http_json("GET", url, token=token, ca_path=ca_path, metric_name="flow_versions_list")


def fetch_observed_version_capabilities(api_base, token, conversations_by_id, target_flows, client_id, ca_path=""):
    """Resolve exact historical flow versions with the fewest possible API calls."""
    pairs = set()
    for conv in conversations_by_id.values():
        visits = extract_flow_visits(conv, target_flows)
        for fid, visit in visits.items():
            for version in visit["versions"]:
                if version:
                    pairs.add((fid, version))

    results = {}
    if not pairs:
        return results, [], {"version_cache_hits": 0, "version_persistent_cache_hits": 0, "version_published_metadata_hits": 0}

    with STATE_LOCK:
        mem_cache = dict(STATE.get("version_cache") or {})
    root, tenant_key, tenant = get_tenant_disk_cache(api_base, client_id)
    disk_versions = tenant.get("version_capabilities") or {}
    cache_hits = persistent_hits = published_hits = 0
    missing = []

    for fid, version in sorted(pairs):
        pair = (fid, version)
        if pair in mem_cache:
            results[pair] = mem_cache[pair]; cache_hits += 1; continue
        disk_key = f"{fid}|{version}"
        if disk_key in disk_versions:
            item = disk_versions[disk_key]
            results[pair] = item; mem_cache[pair] = item; persistent_hits += 1; continue
        meta = target_flows.get(fid, {})
        if str(meta.get("published_version", "")) == str(version):
            pva = meta.get("published_version_virtual_agent_enabled", "")
            pava = meta.get("published_version_agentic_virtual_agent_enabled", "")
            if pva != "" or pava != "":
                va, ava = bool(pva), bool(pava)
                item = {"flow_id": fid, "flow_name": meta.get("flow_name", ""), "flow_version": version,
                        "virtual_agent_enabled": va, "agentic_virtual_agent_enabled": ava,
                        "capability": flow_capability(va, ava), "lookup_error": "",
                        "resolution_source": "current publishedVersion metadata"}
                results[pair] = item; mem_cache[pair] = item; disk_versions[disk_key] = item; published_hits += 1; continue
        missing.append(pair)

    by_flow = defaultdict(list)
    for fid, version in missing:
        by_flow[fid].append(version)
    unresolved = []
    for fid, versions in by_flow.items():
        if len(versions) < 2:
            unresolved.extend((fid, v) for v in versions); continue
        try:
            listing = get_flow_versions_page(api_base, token, fid, 1, 100, ca_path)
            entities = extract_entities(listing); found = set()
            for ent in entities:
                vid = str(ent.get("id") or ent.get("name") or "")
                if vid not in versions or ("virtualAgentEnabled" not in ent and "agenticVirtualAgentEnabled" not in ent):
                    continue
                va = bool(ent.get("virtualAgentEnabled")); ava = bool(ent.get("agenticVirtualAgentEnabled"))
                item = {"flow_id": fid, "flow_name": target_flows.get(fid, {}).get("flow_name", ""), "flow_version": vid,
                        "virtual_agent_enabled": va, "agentic_virtual_agent_enabled": ava,
                        "capability": flow_capability(va, ava), "lookup_error": "", "resolution_source": "flow version list"}
                results[(fid, vid)] = item; mem_cache[(fid, vid)] = item; disk_versions[f"{fid}|{vid}"] = item; found.add(vid)
            unresolved.extend((fid, v) for v in versions if v not in found)
        except Exception:
            unresolved.extend((fid, v) for v in versions)

    if unresolved:
        max_workers = min(6, len(unresolved))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(get_flow_version_detail, api_base, token, fid, version, ca_path): (fid, version) for fid, version in unresolved}
            for future in as_completed(futures):
                fid, version = futures[future]; meta = target_flows.get(fid, {})
                try:
                    detail = future.result(); va = bool(detail.get("virtualAgentEnabled")); ava = bool(detail.get("agenticVirtualAgentEnabled")); err = ""
                except Exception as exc:
                    va = False; ava = False; err = api_error_text(exc)
                item = {"flow_id": fid, "flow_name": meta.get("flow_name", ""), "flow_version": version,
                        "virtual_agent_enabled": va, "agentic_virtual_agent_enabled": ava,
                        "capability": flow_capability(va, ava), "lookup_error": err,
                        "resolution_source": "individual flow version GET"}
                results[(fid, version)] = item
                if not err:
                    mem_cache[(fid, version)] = item; disk_versions[f"{fid}|{version}"] = item

    with STATE_LOCK:
        STATE["version_cache"] = mem_cache
    tenant["version_capabilities"] = disk_versions; root[tenant_key] = tenant; save_disk_cache(root)
    rows = [results[p] for p in sorted(results, key=lambda x: (target_flows.get(x[0], {}).get("flow_name", "").lower(), x[1]))]
    return results, rows, {"version_cache_hits": cache_hits, "version_persistent_cache_hits": persistent_hits, "version_published_metadata_hits": published_hits}

def get_divisions(api_base, token, ca_path=""):
    divisions = {}
    page = 1
    while True:
        params = urllib.parse.urlencode({"pageSize": 100, "pageNumber": page})
        data = http_json("GET", f"{api_base.rstrip('/')}/api/v2/authorization/divisions?{params}",
                         token=token, ca_path=ca_path, metric_name="divisions")
        entities = extract_entities(data)
        for d in entities:
            if d.get("id"):
                divisions[d["id"]] = d.get("name") or d["id"]
        page_count = data.get("pageCount") or data.get("page_count")
        if page_count is not None:
            try:
                if page >= int(page_count):
                    break
            except Exception:
                pass
        if len(entities) < 100:
            break
        page += 1
    return divisions


def get_divisions_by_ids(api_base, token, division_ids, ca_path=""):
    """Resolve only division IDs actually present in matched conversations.

    Genesys supports repeated id query parameters on GET /authorization/divisions.
    Batching keeps this to one call for normal reports and avoids scanning every
    division in a large organization.
    """
    wanted = sorted({str(x) for x in division_ids if x})
    if not wanted:
        return {}
    out = {}
    for batch in chunks(wanted, 50):
        pairs = [("pageSize", "100")] + [("id", x) for x in batch]
        url = f"{api_base.rstrip('/')}/api/v2/authorization/divisions?{urllib.parse.urlencode(pairs)}"
        data = http_json("GET", url, token=token, ca_path=ca_path, metric_name="divisions_targeted")
        for d in extract_entities(data):
            if d.get("id"):
                out[d["id"]] = d.get("name") or d["id"]
    return out


def conversation_division_ids(conversations_by_id):
    ids = set()
    for conv in conversations_by_id.values():
        ids.update(conv.get("divisionIds") or [])
    return ids


def parse_date(s):
    return dt.datetime.strptime(s, "%Y-%m-%d").date()


def utc_iso(local_date, tz_name):
    tz = ZoneInfo(tz_name)
    local_dt = dt.datetime.combine(local_date, dt.time.min, tzinfo=tz)
    return local_dt.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def date_intervals(start_date, end_date_inclusive, tz_name, days_per_chunk=1):
    cur = start_date
    final_exclusive = end_date_inclusive + dt.timedelta(days=1)
    while cur < final_exclusive:
        nxt = min(cur + dt.timedelta(days=days_per_chunk), final_exclusive)
        yield f"{utc_iso(cur, tz_name)}/{utc_iso(nxt, tz_name)}"
        cur = nxt


def chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def analytics_job_submit(api_base, token, interval, flow_ids, ca_path=""):
    body = {"interval": interval, "order": "asc", "orderBy": "conversationStart",
            "segmentFilters": [{"type": "or", "predicates": [
                {"type": "dimension", "dimension": "flowId", "operator": "matches", "value": fid} for fid in flow_ids]}]}
    data = http_json("POST", f"{api_base.rstrip('/')}/api/v2/analytics/conversations/details/jobs",
                     token=token, body=body, timeout=120, ca_path=ca_path, metric_name="analytics_job_create")
    job_id = data.get("jobId") or data.get("id")
    if not job_id:
        raise RuntimeError("Conversation Detail Jobs API did not return a jobId.")
    return str(job_id)


def analytics_job_wait(api_base, token, job_id, ca_path=""):
    url = f"{api_base.rstrip('/')}/api/v2/analytics/conversations/details/jobs/{urllib.parse.quote(job_id, safe='')}"
    started = time.time(); delay = JOB_POLL_INITIAL_SECONDS
    time.sleep(delay)
    while True:
        data = http_json("GET", url, token=token, timeout=90, ca_path=ca_path, metric_name="analytics_job_status")
        state = str(data.get("state") or "").upper()
        if state == "FULFILLED":
            return data
        if state in {"FAILED", "CANCELLED", "EXPIRED"}:
            raise RuntimeError(f"Analytics job {job_id} ended in state {state}: {data.get('errorMessage') or data}")
        if time.time() - started > JOB_TIMEOUT_SECONDS:
            raise RuntimeError(f"Analytics job {job_id} did not complete within {JOB_TIMEOUT_SECONDS} seconds.")
        time.sleep(delay); delay = min(JOB_POLL_MAX_SECONDS, delay * 1.7)


def analytics_job_results(api_base, token, job_id, ca_path=""):
    base = f"{api_base.rstrip('/')}/api/v2/analytics/conversations/details/jobs/{urllib.parse.quote(job_id, safe='')}/results"
    cursor = None; seen = set(); conversations = []; availability = ""
    while True:
        params = {"pageSize": JOB_RESULT_PAGE_SIZE}
        if cursor: params["cursor"] = cursor
        data = http_json("GET", base + "?" + urllib.parse.urlencode(params), token=token, timeout=180,
                         ca_path=ca_path, metric_name="analytics_job_results")
        conversations.extend(data.get("conversations") or [])
        availability = availability or data.get("dataAvailabilityDate") or ""
        next_cursor = data.get("cursor")
        if not next_cursor: break
        if next_cursor in seen: raise RuntimeError("Analytics Jobs API returned a repeated cursor.")
        seen.add(next_cursor); cursor = next_cursor
    return conversations, availability


def run_analytics_jobs(api_base, token, interval, flow_ids, ca_path=""):
    conversations_by_id = {}; job_ids = []; availability_dates = []
    pending_batches = list(chunks(flow_ids, JOB_FLOW_BATCH_SIZE))
    for batch in pending_batches:
        try:
            job_id = analytics_job_submit(api_base, token, interval, batch, ca_path)
            sub_batches = None
        except urllib.error.HTTPError as exc:
            if exc.code == 400 and len(batch) > 1:
                mid = len(batch) // 2; sub_batches = [batch[:mid], batch[mid:]]
            else:
                raise
        if sub_batches:
            for sub in sub_batches:
                sub_id = analytics_job_submit(api_base, token, interval, sub, ca_path)
                analytics_job_wait(api_base, token, sub_id, ca_path)
                convs, availability = analytics_job_results(api_base, token, sub_id, ca_path)
                job_ids.append(sub_id)
                if availability: availability_dates.append(availability)
                for conv in convs:
                    cid = conv.get("conversationId")
                    if cid: conversations_by_id[cid] = conv
            continue
        analytics_job_wait(api_base, token, job_id, ca_path)
        convs, availability = analytics_job_results(api_base, token, job_id, ca_path)
        job_ids.append(job_id)
        if availability: availability_dates.append(availability)
        for conv in convs:
            cid = conv.get("conversationId")
            if cid: conversations_by_id[cid] = conv
    return conversations_by_id, job_ids, sorted(set(availability_dates))

def extract_flow_visits(conversation, target_flows):
    visits = defaultdict(lambda: {
        "count": 0, "versions": set(), "version_counts": defaultdict(int), "purposes": set(), "providers": set(),
        "media_types": set(), "first_seen": "", "last_seen": "",
    })
    for participant in conversation.get("participants") or []:
        purpose = participant.get("purpose") or ""
        for session in participant.get("sessions") or []:
            flow = session.get("flow") or {}
            fid = flow.get("flowId") or ""
            if not fid or fid not in target_flows:
                continue
            v = visits[fid]
            v["count"] += 1
            if flow.get("flowVersion"):
                version = str(flow["flowVersion"])
                v["versions"].add(version)
                v["version_counts"][version] += 1
            if purpose:
                v["purposes"].add(purpose)
            if session.get("provider"):
                v["providers"].add(str(session["provider"]))
            if session.get("mediaType"):
                v["media_types"].add(str(session["mediaType"]))
            starts = []
            ends = []
            for seg in session.get("segments") or []:
                if seg.get("segmentStart"):
                    starts.append(seg["segmentStart"])
                if seg.get("segmentEnd"):
                    ends.append(seg["segmentEnd"])
            if starts:
                s = min(starts)
                if not v["first_seen"] or s < v["first_seen"]:
                    v["first_seen"] = s
            if ends:
                e = max(ends)
                if not v["last_seen"] or e > v["last_seen"]:
                    v["last_seen"] = e
    return visits


def conversation_division_info(conversation, divisions):
    ids = list(dict.fromkeys(conversation.get("divisionIds") or []))
    names = [divisions.get(i, i) for i in ids]
    if len(ids) == 1:
        bucket = names[0]
    elif not ids:
        bucket = "UNKNOWN_DIVISION"
    else:
        bucket = "MULTIPLE_DIVISIONS"
    return ids, names, bucket


def build_reports(conversations_by_id, target_flows, divisions, version_capabilities):
    interaction_rows = []
    conversation_rows = []

    for cid, conv in sorted(conversations_by_id.items(), key=lambda kv: kv[1].get("conversationStart", "")):
        visits = extract_flow_visits(conv, target_flows)
        if not visits:
            continue
        div_ids, div_names, div_bucket = conversation_division_info(conv, divisions)
        matched_flow_ids = sorted(visits)

        version_records = []
        lookup_errors = []
        for fid in matched_flow_ids:
            versions = sorted(visits[fid]["versions"])
            if not versions:
                lookup_errors.append(f"{fid}: Analytics did not return flowVersion")
            for version in versions:
                rec = version_capabilities.get((fid, version))
                if rec:
                    version_records.append(rec)
                    if rec.get("lookup_error"):
                        lookup_errors.append(f"{fid} v{version}: {rec['lookup_error']}")
                else:
                    lookup_errors.append(f"{fid} v{version}: version capability not resolved")

        has_ava = any(r.get("agentic_virtual_agent_enabled") and not r.get("lookup_error") for r in version_records)
        has_va = any(r.get("virtual_agent_enabled") and not r.get("lookup_error") for r in version_records)
        highest = "AVA" if has_ava else ("VA" if has_va else "UNKNOWN")
        estimated_tokens = 1.2 if highest == "AVA" else (0.5 if highest == "VA" else "")
        caps = sorted({r.get("capability", "") for r in version_records if r.get("capability") and not r.get("lookup_error")})

        conversation_rows.append({
            "conversation_id": cid,
            "conversation_start": conv.get("conversationStart", ""),
            "conversation_end": conv.get("conversationEnd", ""),
            "originating_direction": conv.get("originatingDirection", ""),
            "conversation_division_bucket": div_bucket,
            "conversation_division_ids": ";".join(div_ids),
            "conversation_division_names": ";".join(div_names),
            "matched_flow_count": len(matched_flow_ids),
            "matched_flow_ids": ";".join(matched_flow_ids),
            "matched_flow_names": ";".join(target_flows[f]["flow_name"] for f in matched_flow_ids),
            "visited_flow_versions": ";".join(f"{fid}:{','.join(sorted(visits[fid]['versions']))}" for fid in matched_flow_ids),
            "matched_version_capabilities": ";".join(caps),
            "billing_classification": highest,
            "estimated_raw_tokens": estimated_tokens,
            "version_lookup_errors": " | ".join(lookup_errors),
            "note": "Version-aware classification uses the exact flowVersion recorded on the interaction, not the flow's current settings.",
        })

        for fid in matched_flow_ids:
            meta = target_flows[fid]
            v = visits[fid]
            versions = sorted(v["versions"])
            if not versions:
                versions = [""]
            for version in versions:
                rec = version_capabilities.get((fid, version), {}) if version else {}
                version_error = rec.get("lookup_error", "") if rec else "flowVersion missing or unresolved"
                interaction_rows.append({
                    "conversation_id": cid,
                    "conversation_start": conv.get("conversationStart", ""),
                    "conversation_end": conv.get("conversationEnd", ""),
                    "originating_direction": conv.get("originatingDirection", ""),
                    "conversation_division_bucket": div_bucket,
                    "conversation_division_ids": ";".join(div_ids),
                    "conversation_division_names": ";".join(div_names),
                    "flow_id": fid,
                    "flow_name": meta["flow_name"],
                    "flow_type": meta["flow_type"],
                    "flow_division_id": meta["flow_division_id"],
                    "flow_division_name": meta["flow_division_name"],
                    "visited_flow_version": version,
                    "visited_version_virtual_agent_enabled": rec.get("virtual_agent_enabled", "") if rec else "",
                    "visited_version_agentic_virtual_agent_enabled": rec.get("agentic_virtual_agent_enabled", "") if rec else "",
                    "visited_version_capability": rec.get("capability", "") if rec and not version_error else "UNKNOWN",
                    "version_lookup_error": version_error,
                    "current_flow_virtual_agent_enabled": meta["virtual_agent_enabled"],
                    "current_flow_agentic_virtual_agent_enabled": meta["agentic_virtual_agent_enabled"],
                    "current_flow_capability": meta["capability"],
                    "current_published_version": meta["published_version"],
                    "flow_visit_count_for_version": v["version_counts"].get(version, "") if version else "",
                    "participant_purposes": ";".join(sorted(v["purposes"])),
                    "providers": ";".join(sorted(v["providers"])),
                    "media_types": ";".join(sorted(v["media_types"])),
                    "first_flow_segment_start": v["first_seen"],
                    "last_flow_segment_end": v["last_seen"],
                })

    groups = defaultdict(lambda: {"ids": set(), "tokens": 0.0})
    for row in conversation_rows:
        key = (row["conversation_division_bucket"], row["billing_classification"])
        groups[key]["ids"].add(row["conversation_id"])
        if isinstance(row["estimated_raw_tokens"], (int, float)):
            groups[key]["tokens"] += float(row["estimated_raw_tokens"])
    summary_rows = [
        {
            "conversation_division": div,
            "billing_classification": cap,
            "unique_interactions": len(data["ids"]),
            "estimated_raw_tokens": round(data["tokens"], 3) if cap in ("AVA", "VA") else "",
        }
        for (div, cap), data in sorted(groups.items())
    ]
    return interaction_rows, conversation_rows, summary_rows


def csv_bytes(rows):
    if not rows:
        return b""
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()), extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8-sig")


def make_zip_bytes():
    with STATE_LOCK:
        flow_rows = list(STATE["flow_rows"])
        interaction_rows = list(STATE["interaction_rows"])
        conversation_rows = list(STATE["conversation_rows"])
        summary_rows = list(STATE["summary_rows"])
        version_rows = list(STATE["version_rows"])
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("flow_inventory.csv", csv_bytes(flow_rows))
        zf.writestr("interaction_flow_matches.csv", csv_bytes(interaction_rows))
        zf.writestr("interaction_classification.csv", csv_bytes(conversation_rows))
        zf.writestr("summary_by_division.csv", csv_bytes(summary_rows))
        zf.writestr("flow_version_capabilities.csv", csv_bytes(version_rows))
    return bio.getvalue()


def scan_flows(payload):
    api_base = (payload.get("api_base") or DEFAULT_API_BASE).strip().rstrip("/")
    client_id = (payload.get("client_id") or "").strip(); client_secret = payload.get("client_secret") or ""
    ca_path = (payload.get("ca_path") or "").strip(); force_refresh = bool(payload.get("force_refresh"))
    token = get_oauth_token(api_base, client_id, client_secret, ca_path); before = API_METRICS.snapshot()
    root, key, tenant = get_tenant_disk_cache(api_base, client_id)
    cached_rows = tenant.get("flow_rows") if isinstance(tenant.get("flow_rows"), list) else []
    cached_at = float(tenant.get("flow_rows_cached_at") or 0)
    use_cached_flows = bool(cached_rows and not force_refresh and time.time() - cached_at < FLOW_CACHE_TTL_SECONDS)
    detail_errors = {}; flow_detail_calls = 0
    if use_cached_flows:
        rows = cached_rows
    else:
        listed = get_all_flows(api_base, token, ca_path)
        details, detail_errors, flow_detail_calls = enrich_all_flows(api_base, token, listed, ca_path)
        rows = [flow_to_row(flow, detail_errors.get(fid, "")) for fid, flow in details.items()]
        rows.sort(key=lambda r: (r["flow_type"], r["flow_name"].lower()))
        tenant["flow_rows"] = rows; tenant["flow_rows_cached_at"] = time.time()
    target = {r["flow_id"]: r for r in rows if r.get("flow_id") and (r.get("virtual_agent_enabled") or r.get("agentic_virtual_agent_enabled"))}
    # Do not spend an API call enumerating all org divisions during flow discovery.
    # Seed names from flow metadata and merge any cached conversation divisions.
    division_warning = ""
    cached_divisions = tenant.get("divisions") if isinstance(tenant.get("divisions"), dict) else {}
    divisions = {r["flow_division_id"]: r["flow_division_name"] for r in rows if r.get("flow_division_id")}
    divisions.update(cached_divisions)
    root[key] = tenant; save_disk_cache(root); after = API_METRICS.snapshot(); call_diff = ApiMetrics.diff(before, after)
    with STATE_LOCK:
        STATE["flow_rows"] = rows; STATE["target_flows"] = target; STATE["divisions"] = divisions
        STATE["interaction_rows"] = []; STATE["conversation_rows"] = []; STATE["summary_rows"] = []; STATE["version_rows"] = []
        STATE["last_scan_summary"] = {"all_flows": len(rows), "target_flows": len(target),
            "va_only": sum(1 for r in target.values() if r["virtual_agent_enabled"] and not r["agentic_virtual_agent_enabled"]),
            "ava_enabled": sum(1 for r in target.values() if r["agentic_virtual_agent_enabled"]),
            "used_flow_inventory_cache": use_cached_flows, "per_flow_detail_calls": flow_detail_calls,
            "genesys_api_calls_this_scan": sum(v for k,v in call_diff.items() if k != "http_retry_attempts"),
            **{f"api_{k}": v for k,v in call_diff.items()}}
    return {"ok": True, "summary": STATE["last_scan_summary"], "division_warning": division_warning,
            "preview": [r for r in rows if r.get("virtual_agent_enabled") or r.get("agentic_virtual_agent_enabled")][:50]}

def run_interaction_report(payload):
    api_base = (payload.get("api_base") or DEFAULT_API_BASE).strip().rstrip("/")
    client_id = (payload.get("client_id") or "").strip(); client_secret = payload.get("client_secret") or ""
    ca_path = (payload.get("ca_path") or "").strip(); start_date = parse_date(payload.get("start_date") or "")
    end_date = parse_date(payload.get("end_date") or ""); tz_name = (payload.get("timezone") or DEFAULT_TZ).strip()
    if end_date < start_date: raise ValueError("End date must be on or after start date.")
    ZoneInfo(tz_name); token = get_oauth_token(api_base, client_id, client_secret, ca_path)
    with STATE_LOCK:
        target = dict(STATE["target_flows"]); divisions = dict(STATE["divisions"])
    if not target:
        scan_flows(payload)
        with STATE_LOCK:
            target = dict(STATE["target_flows"]); divisions = dict(STATE["divisions"])
    if not target: raise RuntimeError("No VA/AVA-enabled flows were found for this OAuth client's accessible divisions.")
    before = API_METRICS.snapshot(); flow_ids = sorted(target)
    interval = f"{utc_iso(start_date, tz_name)}/{utc_iso(end_date + dt.timedelta(days=1), tz_name)}"
    conversations_by_id, job_ids, availability_dates = run_analytics_jobs(api_base, token, interval, flow_ids, ca_path)
    # Resolve only divisions that actually occur in matched conversations.
    missing_div_ids = conversation_division_ids(conversations_by_id) - set(divisions)
    if missing_div_ids:
        try:
            resolved = get_divisions_by_ids(api_base, token, missing_div_ids, ca_path)
            divisions.update(resolved)
            root, key, tenant = get_tenant_disk_cache(api_base, client_id)
            cached = tenant.get("divisions") if isinstance(tenant.get("divisions"), dict) else {}
            cached.update(resolved); tenant["divisions"] = cached; tenant["divisions_cached_at"] = time.time()
            root[key] = tenant; save_disk_cache(root)
        except Exception:
            pass
    version_capabilities, version_rows, version_stats = fetch_observed_version_capabilities(api_base, token, conversations_by_id, target, client_id, ca_path)
    interaction_rows, conversation_rows, summary_rows = build_reports(conversations_by_id, target, divisions, version_capabilities)
    after = API_METRICS.snapshot(); call_diff = ApiMetrics.diff(before, after)
    report_summary = {"date_range": f"{start_date.isoformat()} to {end_date.isoformat()}", "timezone": tz_name,
        "target_flows": len(target), "analytics_mode": "Conversation Detail Jobs API",
        "analytics_jobs_created": call_diff.get("analytics_job_create",0), "analytics_job_status_polls": call_diff.get("analytics_job_status",0),
        "analytics_result_pages": call_diff.get("analytics_job_results",0), "job_result_page_size": JOB_RESULT_PAGE_SIZE,
        "job_ids": ";".join(job_ids), "data_availability_dates": ";".join(availability_dates),
        "version_api_calls": call_diff.get("flow_version_detail",0)+call_diff.get("flow_versions_list",0),
        "version_memory_cache_hits": version_stats.get("version_cache_hits",0), "version_persistent_cache_hits": version_stats.get("version_persistent_cache_hits",0),
        "version_published_metadata_hits": version_stats.get("version_published_metadata_hits",0), "matched_conversations": len(conversation_rows),
        "conversation_flow_rows": len(interaction_rows), "observed_flow_versions": len(version_rows),
        "flow_version_lookup_errors": sum(1 for r in version_rows if r.get("lookup_error")),
        "ava_classified_conversations": sum(1 for r in conversation_rows if r["billing_classification"]=="AVA"),
        "va_classified_conversations": sum(1 for r in conversation_rows if r["billing_classification"]=="VA"),
        "unknown_classification_conversations": sum(1 for r in conversation_rows if r["billing_classification"]=="UNKNOWN"),
        "estimated_raw_tokens": round(sum(float(r["estimated_raw_tokens"]) for r in conversation_rows if isinstance(r.get("estimated_raw_tokens"),(int,float))),3),
        "genesys_api_calls_this_report": sum(v for k,v in call_diff.items() if k != "http_retry_attempts"),
        **{f"api_{k}":v for k,v in call_diff.items()}}
    with STATE_LOCK:
        STATE["interaction_rows"] = interaction_rows; STATE["conversation_rows"] = conversation_rows; STATE["summary_rows"] = summary_rows
        STATE["version_rows"] = version_rows; STATE["last_report_summary"] = report_summary
    return {"ok": True, "summary": report_summary, "preview": interaction_rows[:50], "summary_rows": summary_rows}


INDEX_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Genesys AVA/VA Division Reporter - Jobs Optimized</title>
<style>:root{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#1f2937;background:#f5f7fa}body{margin:0}.wrap{max-width:1180px;margin:28px auto;padding:0 18px 60px}.card{background:#fff;border:1px solid #dce2e8;border-radius:14px;padding:20px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.04)}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:0 0 14px}p{line-height:1.5}.muted{color:#667085}.warn{background:#fff7e6;border:1px solid #f3d08a;padding:12px;border-radius:9px;margin:10px 0}.ok{color:#067647}.err{color:#b42318}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.grid label{display:block;font-size:13px;font-weight:600;margin-bottom:5px}input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #cfd6df;border-radius:8px;font:inherit}input[type=checkbox]{width:auto;margin-right:7px}button,.btn{display:inline-block;border:0;border-radius:8px;padding:10px 15px;background:#175cd3;color:white;font-weight:600;text-decoration:none;cursor:pointer}.secondary{background:#475467}.download{background:#087443}.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.status{margin:12px 0}.small{font-size:13px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:8px;margin:12px 0}.stat{border:1px solid #e2e8f0;border-radius:8px;padding:9px}.stat span{display:block;font-size:11px;color:#667085;text-transform:uppercase}.stat b{font-size:16px;word-break:break-word}table{border-collapse:collapse;width:100%;font-size:12px;display:block;overflow:auto;max-height:430px}th,td{border:1px solid #e2e8f0;padding:6px 8px;text-align:left;white-space:nowrap}th{background:#f8fafc;position:sticky;top:0}.spinner{display:inline-block;width:13px;height:13px;border:2px solid #ddd;border-top-color:#175cd3;border-radius:50%;animation:s .8s linear infinite;margin-right:7px}@keyframes s{to{transform:rotate(360deg)}}code{background:#f2f4f7;padding:2px 4px;border-radius:4px}@media(max-width:700px){.grid{grid-template-columns:1fr}}</style></head><body><div class="wrap">
<h1>Genesys AVA/VA Division Reporter</h1><p class="muted">Jobs API edition - optimized for historical billing reconciliation with minimal Genesys API consumption.</p>
<div class="warn"><b>Historical data only:</b> Conversation Detail Jobs is data-lake based and is not intended for real-time reporting. Use it for completed billing/reporting periods and compare totals with official Resource Usage.</div>
<div class="card"><h2>Connection</h2><div class="grid"><div><label>Genesys API base</label><input id="api_base" value="https://api.mypurecloud.de"></div><div><label>Timezone for report dates</label><input id="timezone" value="UTC"></div><div><label>OAuth Client ID</label><input id="client_id" autocomplete="off"></div><div><label>OAuth Client Secret</label><input id="client_secret" type="password" autocomplete="new-password"></div><div style="grid-column:1/-1"><label>Corporate CA PEM path (optional)</label><input id="ca_path" placeholder="Leave blank unless IT provided a PEM certificate"></div><div style="grid-column:1/-1"><label><input id="force_refresh" type="checkbox">Force live flow refresh (division names are resolved only for matched conversations)</label></div></div><p class="small muted">Server binds only to 127.0.0.1. Credentials stay in memory. Historical flow-version capability results are cached locally because published versions are immutable.</p></div>
<div class="card"><h2>1. Discover flows</h2><p>Collect all flows visible to the OAuth client and identify VA/AVA-enabled flows. Individual flow GETs are limited to Bot/Digital Bot flows only when the bulk list response omits the capability flags.</p><button onclick="scanFlows()">Scan flows</button><div id="scan_status" class="status"></div><div id="scan_result"></div><div class="actions"><a class="btn download" href="/download/flows">Download flow_inventory.csv</a></div></div>
<div class="card"><h2>2. Run optimized historical report</h2><div class="grid"><div><label>Start date (inclusive)</label><input id="start_date" type="date"></div><div><label>End date (inclusive)</label><input id="end_date" type="date"></div></div><p class="small muted">The full date range is submitted to <code>/analytics/conversations/details/jobs</code> with only the discovered flow IDs. Up to 150 flow predicates are packed into one job. Results are fetched at up to 10,000 conversations per page. Status polling uses adaptive backoff.</p><button onclick="runReport()">Run Jobs API report</button><div id="report_status" class="status"></div><div id="report_result"></div><div class="actions"><a class="btn download" href="/download/matches">Interaction-flow matches CSV</a><a class="btn download" href="/download/conversations">Conversation classification CSV</a><a class="btn download" href="/download/summary">Summary by division CSV</a><a class="btn download" href="/download/versions">Flow version checks CSV</a><a class="btn secondary" href="/download/all">Download all as ZIP</a></div></div>
<div class="card"><h2>API-saving logic</h2><p><b>Analytics:</b> one async job per flow batch for the entire date range, adaptive status polling, and 10,000-result cursor pages. <b>Architect:</b> historical classification checks memory cache, persistent cache, current published-version metadata, a version-list lookup when useful, then an individual version GET only as a last resort. <b>Metadata:</b> flow inventory is cached for 6 hours; only division IDs actually found in matched conversations are resolved and cached.</p></div></div>
<script>function payload(){return {api_base:document.getElementById('api_base').value,timezone:document.getElementById('timezone').value,client_id:document.getElementById('client_id').value,client_secret:document.getElementById('client_secret').value,ca_path:document.getElementById('ca_path').value,start_date:document.getElementById('start_date').value,end_date:document.getElementById('end_date').value,force_refresh:document.getElementById('force_refresh').checked}}function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}function stats(o){return '<div class="stats">'+Object.entries(o||{}).map(([k,v])=>'<div class="stat"><span>'+esc(k.replaceAll('_',' '))+'</span><b>'+esc(v)+'</b></div>').join('')+'</div>'}function table(rows){if(!rows||!rows.length)return '<p class="muted">No rows.</p>';let keys=Object.keys(rows[0]);return '<table><thead><tr>'+keys.map(k=>'<th>'+esc(k)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+keys.map(k=>'<td>'+esc(r[k])+'</td>').join('')+'</tr>').join('')+'</tbody></table>'}async function post(path,statusId,resultId){let s=document.getElementById(statusId),r=document.getElementById(resultId);s.innerHTML='<span class="spinner"></span>Working...';r.innerHTML='';try{let res=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload())});let data=await res.json();if(!res.ok||!data.ok)throw new Error(data.error||('HTTP '+res.status));s.innerHTML='<div class="ok">Completed.</div>';return data}catch(e){s.innerHTML='<div class="err">'+esc(e.message)+'</div>';throw e}}async function scanFlows(){try{let d=await post('/api/scan_flows','scan_status','scan_result');document.getElementById('scan_result').innerHTML=stats(d.summary)+(d.division_warning?'<div class="warn">'+esc(d.division_warning)+'</div>':'')+'<h3>Enabled-flow preview</h3>'+table(d.preview)}catch(e){}}async function runReport(){try{let d=await post('/api/run_report','report_status','report_result');document.getElementById('report_result').innerHTML=stats(d.summary)+'<h3>Summary by division</h3>'+table(d.summary_rows)+'<h3>Match preview</h3>'+table(d.preview)}catch(e){}}let today=new Date();let first=new Date(today.getFullYear(),today.getMonth(),1);document.getElementById('end_date').value=today.toISOString().slice(0,10);document.getElementById('start_date').value=first.toISOString().slice(0,10);</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    server_version = "GenesysAVAReporter/4.0-Jobs"

    def log_message(self, fmt, *args):
        # Avoid accidentally logging form data; standard access log only.
        sys.stdout.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def send_bytes(self, status, content_type, data, filename=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            self.send_bytes(200, "text/html; charset=utf-8", INDEX_HTML.encode("utf-8"))
            return
        if path.startswith("/download/"):
            kind = path.split("/")[-1]
            with STATE_LOCK:
                flow_rows = list(STATE["flow_rows"])
                interaction_rows = list(STATE["interaction_rows"])
                conversation_rows = list(STATE["conversation_rows"])
                summary_rows = list(STATE["summary_rows"])
                version_rows = list(STATE["version_rows"])
            if kind == "flows":
                self.send_bytes(200, "text/csv; charset=utf-8", csv_bytes(flow_rows), "flow_inventory.csv")
            elif kind == "matches":
                self.send_bytes(200, "text/csv; charset=utf-8", csv_bytes(interaction_rows), "interaction_flow_matches.csv")
            elif kind == "conversations":
                self.send_bytes(200, "text/csv; charset=utf-8", csv_bytes(conversation_rows), "interaction_classification.csv")
            elif kind == "summary":
                self.send_bytes(200, "text/csv; charset=utf-8", csv_bytes(summary_rows), "summary_by_division.csv")
            elif kind == "versions":
                self.send_bytes(200, "text/csv; charset=utf-8", csv_bytes(version_rows), "flow_version_capabilities.csv")
            elif kind == "all":
                self.send_bytes(200, "application/zip", make_zip_bytes(), "genesys_ava_va_report.zip")
            else:
                self.send_bytes(404, "text/plain; charset=utf-8", b"Not found")
            return
        self.send_bytes(404, "text/plain; charset=utf-8", b"Not found")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            payload = json.loads(raw.decode("utf-8"))
            if path == "/api/scan_flows":
                result = scan_flows(payload)
            elif path == "/api/run_report":
                result = run_interaction_report(payload)
            else:
                self.send_bytes(404, "application/json", json.dumps({"ok": False, "error": "Not found"}).encode())
                return
            status, ctype, data = json_bytes(result, 200)
            self.send_bytes(status, ctype, data)
        except Exception as exc:
            traceback.print_exc()
            status, ctype, data = json_bytes({"ok": False, "error": api_error_text(exc)}, 500)
            self.send_bytes(status, ctype, data)


def find_port(start=8765, end=8785):
    for port in range(start, end + 1):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            return server, port
        except OSError:
            continue
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    return server, server.server_address[1]


def main():
    server, port = find_port()
    url = f"http://127.0.0.1:{port}/"
    print(f"\n{APP_NAME}")
    print(f"Open this URL in your browser: {url}")
    print("Press Ctrl+C in this Terminal window to stop the app.\n")
    try:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
