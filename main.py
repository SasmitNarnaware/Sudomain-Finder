"""Low-noise, authorized reconnaissance and IDOR-candidate triage.

The scanner only performs discovery and GET-oriented URL collection through the
existing command-line tools.  It never changes a request body, submits a
mutation, or attempts to prove access control impact.  Everything is behind
``main()`` so this module is safe to import from tests and other tooling.
"""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit
from urllib.request import Request, urlopen


VERSION = "2.0"
DEFAULT_USER_AGENT = "Nmap-Subdomain-Finder/2.0 authorized-research"
BANNER = r"""
  _   _       _    __ _
 | | | | __ _| |_ / _(_)_ __   __| |
 | |_| |/ _` | __| |_| | '_ \ / _` |
 |  _  | (_| | |_|  _| | | | | (_| |
 |_| |_|\__,_|\__|_| |_|_| |_|\__,_|
"""
UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
NUMERIC_RE = re.compile(r"^\d{1,20}$")
ID_NAME_RE = re.compile(
    r"(?i)(?:^|[_-])(id|ids|uuid|guid|user|account|customer|client|member|org|organization|project|order|invoice|document|file|record)(?:[_-]|$)"
)
SENSITIVE_NAME_RE = re.compile(r"(?i)(token|secret|password|passwd|session|cookie|auth|api[_-]?key)")
API_SEGMENTS = {
    "api",
    "graphql",
    "rest",
    "rpc",
    "swagger",
    "openapi",
    "v1",
    "v2",
    "v3",
}
RESOURCE_SEGMENTS = {
    "account",
    "accounts",
    "customer",
    "customers",
    "document",
    "documents",
    "file",
    "files",
    "invoice",
    "invoices",
    "member",
    "members",
    "order",
    "orders",
    "organization",
    "organizations",
    "project",
    "projects",
    "record",
    "records",
    "user",
    "users",
}


class ReconError(RuntimeError):
    """An actionable failure that should be shown to the operator."""


def normalize_host(value: str) -> str:
    """Return a lower-case hostname without a trailing dot or URL syntax."""

    raw = (value or "").strip()
    if "://" not in raw:
        raw = "//" + raw
    try:
        host = urlsplit(raw).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".").lower()


def get_domain(value: str) -> str:
    """Validate and normalize the root domain supplied by the operator."""

    domain = normalize_host(value)
    if domain.startswith("www."):
        domain = domain[4:]
    if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", domain):
        raise ValueError("enter a valid root domain, such as example.com")
    return domain


def _scope_pattern(value: str) -> str:
    value = (value or "").strip()
    wildcard = value.startswith("*.")
    normalized = normalize_host(value[2:] if wildcard else value)
    return f"*.{normalized}" if wildcard and normalized else normalized


def _matches_pattern(host: str, pattern: str) -> bool:
    """Match exact names and wildcard subdomains (a bare name includes children)."""

    host = normalize_host(host)
    pattern = _scope_pattern(pattern)
    if not host or not pattern:
        return False
    if pattern.startswith("*."):
        base = pattern[2:]
        return host != base and host.endswith("." + base)
    return host == pattern or host.endswith("." + pattern)


def host_in_scope(host: str, root_domain: str, allow: Sequence[str] | None = None,
                  deny: Sequence[str] | None = None) -> bool:
    """Apply deny-first scope matching to a hostname.

    With no explicit allow list, the root and its subdomains are allowed.  A
    JSON allow list narrows that default; deny always wins.
    """

    host = normalize_host(host)
    root_domain = get_domain(root_domain)
    allow = [item for item in (allow or []) if _scope_pattern(item)]
    deny = [item for item in (deny or []) if _scope_pattern(item)]
    if any(_matches_pattern(host, item) for item in deny):
        return False
    if allow:
        return any(_matches_pattern(host, item) for item in allow)
    return _matches_pattern(host, root_domain)


def load_scope_file(path: str | Path, root_domain: str) -> dict[str, list[str]]:
    """Load ``{"allow": [...], "deny": [...]}`` scope JSON."""

    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise ReconError(f"cannot read scope file {path}: {error}") from error
    if not isinstance(payload, Mapping):
        raise ReconError("scope file must contain a JSON object with allow/deny lists")
    scope: dict[str, list[str]] = {}
    for key in ("allow", "deny"):
        value = payload.get(key, [])
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ReconError(f"scope field '{key}' must be a string or list of strings")
        scope[key] = [_scope_pattern(item) for item in value if _scope_pattern(item)]
    return scope


def normalize_url(url: str, default_scheme: str = "https") -> str:
    """Canonicalize an HTTP(S) URL while retaining query values for analysis."""

    raw = (url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"{default_scheme}://{raw}"
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            return ""
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
        if any(character.isspace() for character in host):
            return ""
        port = parsed.port
        netloc = host
        if port and not ((parsed.scheme.lower() == "http" and port == 80) or
                         (parsed.scheme.lower() == "https" and port == 443)):
            netloc += f":{port}"
        path = parsed.path or "/"
        path = posixpath.normpath("/" + path.lstrip("/"))
        if parsed.path.endswith("/") and not path.endswith("/"):
            path += "/"
        if not path.startswith("/"):
            path = "/" + path
        return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
    except (UnicodeError, ValueError):
        return ""


def normalize_endpoint(url: str) -> str:
    """Return a canonical origin/path endpoint without query or fragment."""

    normalized = normalize_url(url)
    if not normalized:
        return ""
    parsed = urlsplit(normalized)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def extract_endpoint_data(urls: Iterable[str]) -> tuple[list[str], list[str]]:
    """Build deduplicated normalized endpoints and query parameter names."""

    endpoints: set[str] = set()
    parameters: set[str] = set()
    for url in urls:
        normalized = normalize_url(url)
        if not normalized:
            continue
        endpoints.add(normalize_endpoint(normalized))
        parameters.update(name for name, _ in parse_qsl(urlsplit(normalized).query, keep_blank_values=True))
    return sorted(endpoints), sorted(parameters)


def _identifier(value: str, location: str, name: str = "") -> dict[str, str]:
    decoded = unquote(value)
    if UUID_RE.fullmatch(decoded):
        kind = "uuid"
    elif NUMERIC_RE.fullmatch(decoded):
        kind = "numeric"
    else:
        kind = "id-like-name"
    result = {"location": location, "type": kind}
    if name:
        result["name"] = name
    result["value"] = decoded
    return result


def _is_id_like_name(name: str) -> bool:
    compact = re.sub(r"[_-]", "", name.lower())
    return bool(ID_NAME_RE.search(name) or compact.endswith(("id", "uuid", "guid")))


def _redacted_url(url: str) -> str:
    parsed = urlsplit(url)
    pairs = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        pairs.append((name, "[redacted]" if SENSITIVE_NAME_RE.search(name) else value))
    query = "&".join(f"{quote(name, safe='[]-._~')}={quote(value, safe='[]-._~') }" for name, value in pairs)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def extract_idor_candidates(urls: Iterable[str], root_domain: str | None = None,
                            allow: Sequence[str] | None = None,
                            deny: Sequence[str] | None = None) -> list[dict[str, Any]]:
    """Extract URL-only IDOR/access-control triage leads.

    No request is made here and request bodies are deliberately outside the
    input surface.  Scores indicate triage usefulness, never a vulnerability.
    """

    candidates: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    for original in urls:
        normalized = normalize_url(original)
        if not normalized:
            continue
        parsed = urlsplit(normalized)
        if root_domain and not host_in_scope(parsed.hostname or "", root_domain, allow, deny):
            continue
        segments = [unquote(part).lower() for part in parsed.path.split("/") if part]
        identifiers: list[dict[str, str]] = []
        for segment in segments:
            if NUMERIC_RE.fullmatch(segment) or UUID_RE.fullmatch(segment):
                identifiers.append(_identifier(segment, "path"))
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            if NUMERIC_RE.fullmatch(unquote(value)) or UUID_RE.fullmatch(unquote(value)):
                identifiers.append(_identifier(value, "query", name))
            elif _is_id_like_name(name):
                identifiers.append(_identifier(value, "query", name))
        lower_segments = set(segments)
        signals = []
        if lower_segments & API_SEGMENTS:
            signals.append("api path")
        if lower_segments & RESOURCE_SEGMENTS:
            signals.append("resource path")
        if any(segment.startswith("v") and segment[1:].isdigit() for segment in segments):
            if "api path" not in signals:
                signals.append("versioned API path")
        if not identifiers:
            continue
        score = 0.35
        if any(item["location"] == "path" for item in identifiers):
            score += 0.25
        if any(item["location"] == "query" for item in identifiers):
            score += 0.15
        if any(item["type"] == "uuid" for item in identifiers):
            score += 0.10
        score += min(0.20, 0.10 * len(signals))
        score = round(min(score, 0.99), 2)
        confidence = "high" if score >= 0.80 else "medium" if score >= 0.60 else "low"
        key = (normalize_endpoint(normalized), tuple(sorted(f"{item['location']}:{item.get('name', '')}:{item['type']}" for item in identifiers)))
        candidate = candidates.setdefault(key, {
            "url": _redacted_url(normalized),
            "endpoint": normalize_endpoint(normalized),
            "host": parsed.hostname or "",
            "identifiers": identifiers,
            "api_resource_signals": signals,
            "confidence_score": score,
            "confidence": confidence,
            "evidence": "URL-only observation; request bodies and mutations were not inspected or sent.",
            "manual_verification": "manual authorized verification is required: compare authorized identities and methods before making any security claim.",
        })
        candidate["confidence_score"] = max(candidate["confidence_score"], score)
    return sorted(candidates.values(), key=lambda item: (-item["confidence_score"], item["endpoint"]))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Authorized low-noise subdomain and access-control triage")
    parser.add_argument("domain", nargs="?", help="in-scope root domain, such as example.com")
    parser.add_argument("--profile", choices=("bugbounty", "thorough"), default="bugbounty",
                        help="scan posture (default: low-noise bugbounty)")
    parser.add_argument("--scope-file", help="JSON file with optional allow and deny hostname lists")
    parser.add_argument("--output-dir", default="runs", help="parent directory for a new run directory")
    parser.add_argument("--run-dir", help="write this run to an explicit directory")
    parser.add_argument("--workers", type=int, help="parallel host workers")
    parser.add_argument("--rate-limit", type=int, help="approximate requests per second for supported tools")
    parser.add_argument("--timeout", type=int, help="per-tool/request timeout in seconds")
    parser.add_argument("--crawl-depth", type=int, help="Katana crawl depth")
    parser.add_argument("--max-hosts", type=int, default=100, help="maximum in-scope live hosts to crawl")
    parser.add_argument("--no-crtsh", action="store_true", help="skip the passive crt.sh source")
    parser.add_argument("--no-katana", action="store_true", help="skip Katana crawling")
    parser.add_argument("--no-gau", action="store_true", help="skip gau historical URLs")
    parser.add_argument("--nmap", action="store_true", help="explicitly run low-noise Nmap service detection")
    parser.add_argument("--nmap-top-ports", type=int, default=100, help="Nmap top ports when --nmap is used")
    args = parser.parse_args(argv)
    defaults = {
        "bugbounty": {"workers": 3, "rate_limit": 5, "timeout": 10, "crawl_depth": 2},
        "thorough": {"workers": 6, "rate_limit": 15, "timeout": 20, "crawl_depth": 3},
    }[args.profile]
    for key, value in defaults.items():
        if getattr(args, key) is None:
            setattr(args, key, value)
    if args.workers < 1 or args.rate_limit < 1 or args.timeout < 1 or args.crawl_depth < 1 or args.max_hosts < 1:
        parser.error("workers, rate-limit, timeout, crawl-depth, and max-hosts must be positive")
    if not 1 <= args.nmap_top_ports <= 65535:
        parser.error("nmap-top-ports must be between 1 and 65535")
    return args


def tool_preflight(run_nmap: bool, skip_katana: bool, skip_gau: bool) -> dict[str, Any]:
    tools = {"subfinder": True, "httpx": True}
    if not skip_katana:
        tools["katana"] = True
    if not skip_gau:
        tools["gau"] = True
    if run_nmap:
        tools["nmap"] = True
    paths = {name: shutil.which(name) for name in tools}
    missing_required = [name for name in ("subfinder", "httpx") if not paths[name]]
    missing_optional = [name for name in tools if name not in ("subfinder", "httpx") and not paths[name]]
    if missing_required:
        raise ReconError("required tool(s) not found on PATH: " + ", ".join(missing_required))
    if run_nmap and not paths.get("nmap"):
        raise ReconError("--nmap was requested, but nmap was not found on PATH")
    return {"available": paths, "missing_optional": missing_optional}


def _run_command(command: Sequence[str], timeout: int, label: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(list(command), capture_output=True, text=True, timeout=timeout,
                              check=False, encoding="utf-8", errors="replace")
    except FileNotFoundError as error:
        raise ReconError(f"{label}: executable not found ({command[0]})") from error
    except subprocess.TimeoutExpired as error:
        raise ReconError(f"{label}: timed out after {timeout}s") from error
    except OSError as error:
        raise ReconError(f"{label}: could not start: {error}") from error


def crtsh_subdomains(root_domain: str, timeout: int) -> set[str]:
    request = Request(f"https://crt.sh/?q=%25.{root_domain}&output=json",
                      headers={"User-Agent": DEFAULT_USER_AGENT})
    try:
        with urlopen(request, timeout=timeout) as response:
            certificates = json.load(response)
    except Exception as error:
        raise ReconError(f"crt.sh: {error}") from error
    names = set()
    for certificate in certificates if isinstance(certificates, list) else []:
        for name in str(certificate.get("name_value", "")).splitlines():
            host = normalize_host(name.lstrip("*."))
            if host and host_in_scope(host, root_domain):
                names.add(host)
    return names


def subfinder_subdomains(root_domain: str, timeout: int, rate_limit: int) -> set[str]:
    command = ["subfinder", "-d", root_domain, "-silent", "-rl", str(rate_limit)]
    result = _run_command(command, max(timeout, 30), "subfinder")
    if result.returncode:
        detail = result.stderr.strip() or f"exit code {result.returncode}"
        raise ReconError(f"subfinder failed: {detail}")
    return {normalize_host(line) for line in result.stdout.splitlines() if normalize_host(line)}


def _new_run_dir(base: str, explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit)
        path.mkdir(parents=True, exist_ok=True)
        return path
    parent = Path(base)
    parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
    path = parent / stamp
    suffix = 1
    while path.exists():
        path = parent / f"{stamp}-{suffix}"
        suffix += 1
    path.mkdir()
    return path


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_recon(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    started_at = datetime.now(timezone.utc).isoformat()
    supplied_domain = args.domain or input("Enter the authorized root domain: ").strip()
    domain = get_domain(supplied_domain)
    scope = load_scope_file(args.scope_file, domain) if args.scope_file else {"allow": [], "deny": []}
    preflight = tool_preflight(args.nmap, args.no_katana, args.no_gau)
    use_katana = not args.no_katana and bool(preflight["available"].get("katana"))
    use_gau = not args.no_gau and bool(preflight["available"].get("gau"))
    if preflight["missing_optional"]:
        print("[!] optional tool(s) unavailable; skipping: " + ", ".join(preflight["missing_optional"]),
              file=sys.stderr)
    run_dir = _new_run_dir(args.output_dir, args.run_dir)
    errors: list[str] = []
    discovered = {domain} if host_in_scope(domain, domain, scope["allow"], scope["deny"]) else set()
    try:
        discovered.update(host for host in subfinder_subdomains(domain, args.timeout, args.rate_limit)
                          if host_in_scope(host, domain, scope["allow"], scope["deny"]))
    except ReconError as error:
        errors.append(str(error))
        raise
    if not args.no_crtsh:
        try:
            discovered.update(host for host in crtsh_subdomains(domain, args.timeout)
                              if host_in_scope(host, domain, scope["allow"], scope["deny"]))
        except ReconError as error:
            errors.append(str(error))
            print(f"[!] {error}", file=sys.stderr)
    discovered = set(sorted(discovered))
    (run_dir / "subdomains.txt").write_text("\n".join(sorted(discovered)) + "\n", encoding="utf-8")

    httpx_command = ["httpx", "-l", str(run_dir / "subdomains.txt"), "-silent", "-json",
                     "-title", "-tech-detect", "-server", "-web-server", "-status-code",
                     "-timeout", str(args.timeout), "-threads", str(args.workers),
                     "-rl", str(args.rate_limit)]
    httpx_result = _run_command(httpx_command, max(args.timeout * 3, 60), "httpx")
    if httpx_result.returncode:
        detail = httpx_result.stderr.strip() or f"exit code {httpx_result.returncode}"
        raise ReconError(f"httpx failed: {detail}")

    subdomains: dict[str, dict[str, Any]] = {}
    for line_number, line in enumerate(httpx_result.stdout.splitlines(), 1):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as error:
            errors.append(f"httpx line {line_number}: invalid JSON ({error.msg})")
            continue
        host = normalize_host(str(data.get("host") or data.get("input") or ""))
        if not host_in_scope(host, domain, scope["allow"], scope["deny"]):
            continue
        header_raw = data.get("headers", data.get("header", {}))
        headers = {str(k).lower(): str(v) for k, v in header_raw.items()} if isinstance(header_raw, Mapping) else {}
        ip_values = data.get("a", [])
        subdomains[host] = {
            "url": normalize_url(str(data.get("url") or f"https://{host}")),
            "ip": str(ip_values[0]) if isinstance(ip_values, list) and ip_values else "",
            "status_code": data.get("status_code"),
            "title": data.get("title"),
            "web_server": data.get("webserver"),
            "technologies": data.get("tech", []),
            "headers": {key: headers.get(key, "") for key in
                        ("content-security-policy", "strict-transport-security", "x-frame-options")},
            "urls": [], "endpoints": [], "parameters": [], "js_files": [], "nmap_scan": "", "errors": [],
        }
        if not subdomains[host]["ip"]:
            try:
                subdomains[host]["ip"] = socket.gethostbyname(host)
            except OSError as error:
                subdomains[host]["errors"].append(f"DNS lookup failed: {error}")

    alive_hosts = sorted(subdomains)[:args.max_hosts]
    (run_dir / "alive.txt").write_text("\n".join(alive_hosts) + "\n", encoding="utf-8")

    def analyze_host(host: str) -> None:
        info = subdomains[host]
        source_url = info["url"] or f"https://{host}"
        urls: set[str] = {source_url}
        if use_katana:
            command = ["katana", "-u", source_url, "-silent", "-depth", str(args.crawl_depth),
                       "-timeout", str(args.timeout), "-rate-limit", str(args.rate_limit)]
            try:
                result = _run_command(command, max(args.timeout * 3, 60), f"katana {host}")
                if result.returncode:
                    raise ReconError(result.stderr.strip() or f"exit code {result.returncode}")
                urls.update(normalize_url(item) for item in result.stdout.splitlines() if normalize_url(item))
            except ReconError as error:
                info["errors"].append(str(error))
        if use_gau:
            command = ["gau", host, "--threads", str(args.workers), "--timeout", str(args.timeout)]
            try:
                result = _run_command(command, max(args.timeout * 3, 60), f"gau {host}")
                if result.returncode:
                    raise ReconError(result.stderr.strip() or f"exit code {result.returncode}")
                urls.update(normalize_url(item) for item in result.stdout.splitlines() if normalize_url(item))
            except ReconError as error:
                info["errors"].append(str(error))
        info["urls"] = sorted(url for url in urls if url and host_in_scope(urlsplit(url).hostname or "", domain,
                                                                            scope["allow"], scope["deny"]))
        info["endpoints"], info["parameters"] = extract_endpoint_data(info["urls"])
        info["js_files"] = [url for url in info["urls"] if urlsplit(url).path.lower().endswith(".js")]
        if args.nmap:
            command = ["nmap", "-Pn", "-sV", "--version-light", "--top-ports", str(args.nmap_top_ports),
                       "-T2", "--max-retries", "1", "--host-timeout", f"{args.timeout}s", host]
            try:
                result = _run_command(command, max(args.timeout * 2, 60), f"nmap {host}")
                if result.returncode:
                    raise ReconError(result.stderr.strip() or f"exit code {result.returncode}")
                info["nmap_scan"] = result.stdout.strip()
            except ReconError as error:
                info["errors"].append(str(error))

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(analyze_host, host): host for host in alive_hosts}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as error:  # keep a host failure visible and continue other hosts
                host = futures[future]
                subdomains[host]["errors"].append(f"unexpected host analysis failure: {error}")
                errors.append(f"{host}: {error}")

    all_urls = [url for host in alive_hosts for url in subdomains[host]["urls"]]
    candidates = extract_idor_candidates(all_urls, domain, scope["allow"], scope["deny"])
    results = {
        "version": VERSION,
        "domain": domain,
        "profile": args.profile,
        "run": {"started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
                "directory": str(run_dir)},
        "scope": scope,
        "preflight": preflight,
        "controls": {"workers": args.workers, "rate_limit": args.rate_limit, "timeout": args.timeout,
                      "crawl_depth": args.crawl_depth, "max_hosts": args.max_hosts, "nmap": args.nmap},
        "subdomains": subdomains,
        "errors": errors,
    }
    _write_json(run_dir / "results.json", results)
    _write_json(run_dir / "manifest.json", {
        "version": VERSION,
        "domain": domain,
        "profile": args.profile,
        "started_at": started_at,
        "finished_at": results["run"]["finished_at"],
        "directory": str(run_dir),
        "controls": results["controls"],
        "scope": scope,
        "preflight": preflight,
        "counts": {
            "discovered_names": len(discovered),
            "live_hosts": len(alive_hosts),
            "urls": len(all_urls),
            "idor_candidates": len(candidates),
        },
    })
    _write_json(run_dir / "idor_candidates.json", {"notice": "Candidates require manual authorized verification; no finding is claimed.",
                                                      "candidates": candidates})
    summary = [
        "Authorized reconnaissance summary",
        f"Domain: {domain}",
        f"Profile: {args.profile} (observation-only, no mutations)",
        f"Run directory: {run_dir}",
        f"Discovered in-scope names: {len(discovered)}",
        f"Live hosts: {len(alive_hosts)}",
        f"Normalized URLs: {len(all_urls)}",
        f"IDOR/access-control triage candidates: {len(candidates)}",
        f"Recorded errors: {len(errors) + sum(len(subdomains[h]['errors']) for h in alive_hosts)}",
        "Candidates are leads for manual authorized verification, not vulnerability findings.",
    ]
    (run_dir / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary))
    return run_dir, results


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        print("\033[96m" + BANNER + "\033[0m")
        print("\033[92m[*] Hatfind — authorized reconnaissance and access-control triage\033[0m")
        print("-" * 72)
        run_recon(args)
        return 0
    except (ValueError, ReconError) as error:
        print(f"[!] {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("[!] interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
