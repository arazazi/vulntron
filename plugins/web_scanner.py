"""
Web application scanner module for Vultron P8.

Performs safe, non-exploit, non-destructive HTTP/HTTPS checks against
web targets discovered from scan inventory or supplied by the user.

Design goals
------------
- Non-invasive: no payloads intended to exploit vulnerabilities.
- Conservative: low request volume, configurable concurrency and timeouts.
- Evidence-based: every finding includes request/response evidence, but
  secrets, cookies values, and auth material are redacted before storage.
- Heuristic where needed: confidence levels reflect the certainty of each check.

Finding IDs
-----------
WEB-HEADER-*        Missing or weak HTTP security header.
WEB-COOKIE-*        Cookie missing security flag.
WEB-REDIRECT-*      HTTP → HTTPS redirect posture.
WEB-CORS-*          CORS misconfiguration heuristic.
WEB-DIRLIST-*       Possible directory listing enabled.
WEB-ROBOTS-INFO     robots.txt / sitemap.xml present (informational).
WEB-BANNER-INFO     Server/technology banner exposed (informational).
WEB-BASICAUTH-INFO  HTTP Basic Auth endpoint exposed (informational).
WEB-CACHE-*         Potentially unsafe cache-control for sensitive pages.
"""

from __future__ import annotations

import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Optional HTTP library — graceful fallback
try:
    import requests as _requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from .secrets import REDACTED

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Default timeout for each HTTP request (seconds).
DEFAULT_TIMEOUT: float = 10.0

#: Default maximum concurrent web checks.
DEFAULT_CONCURRENCY: int = 5

#: Default User-Agent sent with every request.
DEFAULT_USER_AGENT: str = (
    "Vultron-WebScanner/8.0 (authorized security assessment; non-exploit)"
)

#: Ports commonly used for HTTP/HTTPS services.
HTTP_PORTS = {80, 8080, 8000, 8008}
HTTPS_PORTS = {443, 8443, 4443}
WEB_PORTS = HTTP_PORTS | HTTPS_PORTS

#: Paths to probe for directory listing heuristics.
_DIR_PATHS = ["/", "/images/", "/css/", "/js/", "/assets/", "/static/"]

#: Regex patterns suggesting autoindex / directory listing in HTML.
_DIRLIST_PATTERNS = [
    re.compile(r"Index of /", re.IGNORECASE),
    re.compile(r"Parent Directory", re.IGNORECASE),
    re.compile(r"<title>Index of", re.IGNORECASE),
    re.compile(r"\[To Parent Directory\]", re.IGNORECASE),
]

#: Regex for inline auth material that should be redacted from evidence.
_AUTH_REDACT_RE = re.compile(
    r"(?i)(authorization|cookie|set-cookie|www-authenticate"
    r"|x-api-key|x-auth-token|bearer|basic\s+[A-Za-z0-9+/=]+)",
    re.IGNORECASE,
)

#: Headers whose *value* should be redacted.
_SENSITIVE_RESPONSE_HEADERS = frozenset([
    "set-cookie",
    "cookie",
    "authorization",
    "www-authenticate",
    "proxy-authenticate",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
])

#: Recommended security headers and their minimum expectations.
_SECURITY_HEADERS: List[Tuple[str, str, str]] = [
    # (header_name, finding_id_suffix, description)
    ("Content-Security-Policy",   "CSP",        "Content-Security-Policy (CSP)"),
    ("Strict-Transport-Security", "HSTS",       "HTTP Strict Transport Security (HSTS)"),
    ("X-Frame-Options",           "XFO",        "X-Frame-Options"),
    ("X-Content-Type-Options",    "XCTO",       "X-Content-Type-Options"),
    ("Referrer-Policy",           "RP",         "Referrer-Policy"),
    ("Permissions-Policy",        "PP",         "Permissions-Policy"),
]

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class WebFinding:
    """A single finding produced by the web scanner.

    Attributes
    ----------
    finding_id:   Short identifier (e.g. ``WEB-HEADER-CSP``).
    title:        Human-readable title.
    description:  Full description of the issue.
    severity:     One of CRITICAL / HIGH / MEDIUM / LOW / INFO.
    confidence:   Float 0.0–1.0.
    target_url:   The URL that was checked.
    evidence:     List of safe (redacted) evidence strings.
    remediation:  Short remediation guidance.
    """

    finding_id: str
    title: str
    description: str
    severity: str
    confidence: float
    target_url: str
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_label": _confidence_label(self.confidence),
            "target_url": self.target_url,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class WebTargetResult:
    """All findings for a single web target URL.

    Attributes
    ----------
    url:       Canonical base URL (e.g. ``https://10.0.0.1:443``).
    findings:  List of WebFinding objects.
    error:     Optional error string if the target was unreachable.
    """

    url: str
    findings: List[WebFinding] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": self.finding_count,
            "error": self.error,
        }


@dataclass
class WebPostureReport:
    """Aggregated web posture report across all scanned targets.

    Attributes
    ----------
    targets:    Per-target results.
    summary:    Counts by severity.
    """

    targets: List[WebTargetResult] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(t.finding_count for t in self.targets)

    @property
    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        for t in self.targets:
            for f in t.findings:
                key = f.severity.lower()
                if key in counts:
                    counts[key] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "targets": [t.to_dict() for t in self.targets],
            "target_count": len(self.targets),
            "total_findings": self.total_findings,
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _confidence_label(score: float) -> str:
    if score >= 0.75:
        return "HIGH"
    if score >= 0.45:
        return "MEDIUM"
    return "LOW"


def canonicalize_url(raw: str) -> Optional[str]:
    """Return a canonical base URL string, or None if unparseable.

    Examples
    --------
    >>> canonicalize_url("http://example.com/path?q=1")
    'http://example.com'
    >>> canonicalize_url("https://host:8443/")
    'https://host:8443'
    >>> canonicalize_url("example.com")
    'http://example.com'
    """
    raw = raw.strip()
    if not raw:
        return None
    # Inject scheme if missing so urllib.parse works correctly.
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    port = parsed.port
    # Omit default ports from canonical form.
    if port and ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        port = None
    if port:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def dedupe_urls(urls: List[str]) -> List[str]:
    """Canonicalize and deduplicate a list of URL strings."""
    seen: set = set()
    result: List[str] = []
    for raw in urls:
        canonical = canonicalize_url(raw)
        if canonical and canonical not in seen:
            seen.add(canonical)
            result.append(canonical)
    return result


def _build_targets_from_scan(results: Dict) -> List[str]:
    """Discover HTTP/HTTPS targets from existing scan results.

    Looks at open TCP ports and inventory data to find web services.
    """
    target_host = results.get("target", "")
    urls: List[str] = []

    open_ports = results.get("open_ports", [])
    for port_info in open_ports:
        port = port_info.get("port")
        if not isinstance(port, int):
            continue
        scheme = "https" if port in HTTPS_PORTS else ("http" if port in HTTP_PORTS else None)
        if scheme is None:
            # Also accept service names
            svc = (port_info.get("service") or "").upper()
            if "HTTPS" in svc or port in HTTPS_PORTS:
                scheme = "https"
            elif "HTTP" in svc or port in HTTP_PORTS:
                scheme = "http"
        if scheme and target_host:
            urls.append(f"{scheme}://{target_host}:{port}")

    return urls


def _redact_header_value(header_name: str, value: str) -> str:
    """Redact sensitive header values before storing as evidence."""
    if header_name.lower() in _SENSITIVE_RESPONSE_HEADERS:
        return REDACTED
    return value


def _safe_headers_dict(headers: Any) -> Dict[str, str]:
    """Return a redacted copy of a response headers dict."""
    result: Dict[str, str] = {}
    for k, v in dict(headers).items():
        result[k] = _redact_header_value(k, str(v))
    return result


def _make_session(user_agent: str, timeout: float) -> Any:
    """Build a requests.Session configured for safe scanning."""
    if not _HAS_REQUESTS:
        return None
    session = _requests.Session()
    session.headers.update({"User-Agent": user_agent})
    session.max_redirects = 5
    return session


# ---------------------------------------------------------------------------
# Per-check logic
# ---------------------------------------------------------------------------


def _check_security_headers(
    base_url: str,
    session: Any,
    timeout: float,
) -> List[WebFinding]:
    """Check for missing or weak HTTP security response headers."""
    findings: List[WebFinding] = []
    try:
        resp = session.get(base_url + "/", verify=False, timeout=timeout, allow_redirects=True)
    except Exception as exc:
        return findings  # unreachable — outer loop will handle

    headers = resp.headers
    status_ev = f"HTTP {resp.status_code} from {base_url}/"

    for hdr_name, fid_suffix, hdr_desc in _SECURITY_HEADERS:
        if hdr_name not in headers:
            findings.append(WebFinding(
                finding_id=f"WEB-HEADER-{fid_suffix}",
                title=f"Missing security header: {hdr_desc}",
                description=(
                    f"The response from {base_url} does not include the "
                    f"{hdr_desc} header.  Without this header, browsers "
                    "lack an important layer of protection."
                ),
                severity="MEDIUM",
                confidence=0.9,
                target_url=base_url,
                evidence=[status_ev, f"Header absent: {hdr_name}"],
                remediation=(
                    f"Configure your web server or application to set the "
                    f"{hdr_name} header in all responses."
                ),
            ))

    # Warn when CSP is present but overly permissive (unsafe-inline / unsafe-eval / wildcard)
    csp_value = headers.get("Content-Security-Policy", "")
    if csp_value:
        issues = []
        if "'unsafe-inline'" in csp_value:
            issues.append("'unsafe-inline' detected")
        if "'unsafe-eval'" in csp_value:
            issues.append("'unsafe-eval' detected")
        if re.search(r"default-src\s+\*", csp_value) or re.search(r"script-src\s+\*", csp_value):
            issues.append("wildcard source (*) in default-src or script-src")
        if issues:
            findings.append(WebFinding(
                finding_id="WEB-HEADER-CSP-WEAK",
                title="Permissive Content-Security-Policy",
                description=(
                    f"The CSP header at {base_url} contains directives that weaken "
                    "its protection: " + "; ".join(issues) + "."
                ),
                severity="LOW",
                confidence=0.8,
                target_url=base_url,
                evidence=[status_ev, f"CSP: {csp_value[:200]}"],
                remediation=(
                    "Review and tighten your Content-Security-Policy. "
                    "Avoid 'unsafe-inline', 'unsafe-eval', and wildcard sources."
                ),
            ))

    return findings


def _check_cookie_flags(
    base_url: str,
    session: Any,
    timeout: float,
) -> List[WebFinding]:
    """Check session-like cookies for missing Secure, HttpOnly, SameSite flags."""
    findings: List[WebFinding] = []
    try:
        resp = session.get(base_url + "/", verify=False, timeout=timeout, allow_redirects=True)
    except Exception:
        return findings

    is_https = base_url.startswith("https://")
    for cookie in resp.cookies:
        name = cookie.name or "unknown"
        issues = []
        # Redact the actual cookie value — never store it
        if not cookie.secure and is_https:
            issues.append("Secure flag missing")
        if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(cookie, "has_nonstandard_attr", lambda x: False)("httponly"):
            # requests stores HttpOnly as a non-standard attr
            raw = str(resp.headers.get("set-cookie", "")).lower()
            if "httponly" not in raw:
                issues.append("HttpOnly flag missing")
        samesite_re = re.search(r"samesite=(\w+)", str(resp.headers.get("set-cookie", "")), re.I)
        if not samesite_re:
            issues.append("SameSite attribute missing")

        if issues:
            findings.append(WebFinding(
                finding_id="WEB-COOKIE-FLAGS",
                title=f"Cookie missing security flags: {', '.join(issues)}",
                description=(
                    f"A cookie named '{name}' at {base_url} is missing "
                    "recommended security flags: " + "; ".join(issues) + "."
                ),
                severity="LOW",
                confidence=0.7,
                target_url=base_url,
                evidence=[
                    f"Cookie name: {name} (value redacted)",
                    f"Issues: {'; '.join(issues)}",
                ],
                remediation=(
                    "Set the Secure, HttpOnly, and SameSite=Strict (or Lax) "
                    "attributes on all session cookies."
                ),
            ))
    return findings


def _check_http_to_https_redirect(
    base_url: str,
    session: Any,
    timeout: float,
) -> List[WebFinding]:
    """Verify that HTTP endpoints redirect to HTTPS."""
    if not base_url.startswith("http://"):
        return []
    findings: List[WebFinding] = []
    try:
        resp = session.get(base_url + "/", verify=False, timeout=timeout, allow_redirects=False)
    except Exception:
        return findings

    status = resp.status_code
    location = resp.headers.get("Location", "")
    if status in (301, 302, 307, 308) and location.lower().startswith("https://"):
        return []  # Correct redirect

    findings.append(WebFinding(
        finding_id="WEB-REDIRECT-NO-HTTPS",
        title="HTTP endpoint does not redirect to HTTPS",
        description=(
            f"The HTTP endpoint at {base_url} does not issue an HTTPS redirect. "
            "Traffic between clients and the server may be transmitted in cleartext."
        ),
        severity="MEDIUM",
        confidence=0.85,
        target_url=base_url,
        evidence=[
            f"HTTP {status} from {base_url}/",
            f"Location header: {location or '(none)'}",
        ],
        remediation=(
            "Configure the web server to issue a 301 redirect from HTTP to HTTPS "
            "for all requests."
        ),
    ))
    return findings


def _check_cors(
    base_url: str,
    session: Any,
    timeout: float,
) -> List[WebFinding]:
    """Heuristic CORS misconfiguration check (safe, non-exploit)."""
    findings: List[WebFinding] = []
    probe_origin = "https://evil.example.com"
    try:
        resp = session.get(
            base_url + "/",
            headers={"Origin": probe_origin},
            verify=False,
            timeout=timeout,
            allow_redirects=True,
        )
    except Exception:
        return findings

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*" and acac.lower() == "true":
        findings.append(WebFinding(
            finding_id="WEB-CORS-WILDCARD-CREDS",
            title="CORS: wildcard origin with credentials allowed",
            description=(
                f"{base_url} returns Access-Control-Allow-Origin: * combined with "
                "Access-Control-Allow-Credentials: true.  Browsers reject this "
                "combination, but misconfigurations nearby may still expose data."
            ),
            severity="MEDIUM",
            confidence=0.8,
            target_url=base_url,
            evidence=[
                f"Access-Control-Allow-Origin: {acao}",
                f"Access-Control-Allow-Credentials: {acac}",
            ],
            remediation=(
                "Do not use wildcard (*) with Allow-Credentials: true.  "
                "Explicitly list allowed origins and validate them server-side."
            ),
        ))
    elif acao == probe_origin:
        # Server reflects the Origin header — potential misconfiguration
        findings.append(WebFinding(
            finding_id="WEB-CORS-REFLECT-ORIGIN",
            title="CORS: server reflects arbitrary Origin header",
            description=(
                f"{base_url} reflects any supplied Origin value in "
                "Access-Control-Allow-Origin, which may allow cross-origin "
                "requests from arbitrary domains."
            ),
            severity="MEDIUM",
            confidence=0.7,
            target_url=base_url,
            evidence=[
                f"Probe Origin sent: {probe_origin}",
                f"Access-Control-Allow-Origin returned: {acao}",
            ],
            remediation=(
                "Validate the Origin header against an explicit allowlist "
                "before echoing it in Access-Control-Allow-Origin."
            ),
        ))
    return findings


def _check_directory_listing(
    base_url: str,
    session: Any,
    timeout: float,
    max_paths: int = 3,
) -> List[WebFinding]:
    """Heuristic check for enabled directory listing (autoindex)."""
    findings: List[WebFinding] = []
    paths_checked = 0
    for path in _DIR_PATHS:
        if paths_checked >= max_paths:
            break
        url = base_url + path
        try:
            resp = session.get(url, verify=False, timeout=timeout, allow_redirects=True)
        except Exception:
            continue
        paths_checked += 1
        if resp.status_code != 200:
            continue
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            continue
        body = resp.text[:4096]
        for pat in _DIRLIST_PATTERNS:
            if pat.search(body):
                findings.append(WebFinding(
                    finding_id="WEB-DIRLIST",
                    title=f"Possible directory listing enabled at {path}",
                    description=(
                        f"The path {url} appears to return an auto-generated "
                        "directory index, which may expose file and directory names."
                    ),
                    severity="LOW",
                    confidence=0.75,
                    target_url=url,
                    evidence=[
                        f"HTTP {resp.status_code} from {url}",
                        f"Pattern matched: {pat.pattern}",
                    ],
                    remediation=(
                        "Disable directory listing (e.g. 'Options -Indexes' in Apache, "
                        "'autoindex off' in Nginx)."
                    ),
                ))
                break  # one finding per path
    return findings


def _check_robots_sitemap(
    base_url: str,
    session: Any,
    timeout: float,
) -> List[WebFinding]:
    """Informational check: robots.txt and sitemap.xml presence."""
    findings: List[WebFinding] = []
    for path, fid, label in [
        ("/robots.txt",   "WEB-ROBOTS-INFO",  "robots.txt"),
        ("/sitemap.xml",  "WEB-SITEMAP-INFO",  "sitemap.xml"),
    ]:
        url = base_url + path
        try:
            resp = session.get(url, verify=False, timeout=timeout, allow_redirects=False)
        except Exception:
            continue
        if resp.status_code == 200:
            findings.append(WebFinding(
                finding_id=fid,
                title=f"{label} present (informational)",
                description=(
                    f"{label} is publicly accessible at {url}.  "
                    "This is normal for most web applications and is informational only; "
                    "however, Disallow entries in robots.txt may reveal sensitive paths."
                ),
                severity="INFO",
                confidence=0.95,
                target_url=url,
                evidence=[f"HTTP {resp.status_code} from {url}"],
                remediation=(
                    "Review robots.txt Disallow entries to ensure they do not disclose "
                    "sensitive application paths."
                ),
            ))
    return findings


def _check_server_banner(
    base_url: str,
    session: Any,
    timeout: float,
) -> List[WebFinding]:
    """Informational: detect Server / X-Powered-By header disclosure."""
    findings: List[WebFinding] = []
    try:
        resp = session.get(base_url + "/", verify=False, timeout=timeout, allow_redirects=True)
    except Exception:
        return findings

    for hdr in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        value = resp.headers.get(hdr, "")
        if value:
            findings.append(WebFinding(
                finding_id="WEB-BANNER-INFO",
                title=f"Server technology disclosed via {hdr} header",
                description=(
                    f"The response from {base_url} includes the {hdr} header "
                    f"with value '{value[:80]}', which may reveal server software "
                    "and version information to potential attackers."
                ),
                severity="INFO",
                confidence=0.9,
                target_url=base_url,
                evidence=[f"{hdr}: {value[:80]}"],
                remediation=(
                    f"Configure the web server to suppress or anonymise the {hdr} header."
                ),
            ))
    return findings


def _check_basic_auth(
    base_url: str,
    session: Any,
    timeout: float,
) -> List[WebFinding]:
    """Informational: detect HTTP Basic Auth challenge."""
    findings: List[WebFinding] = []
    try:
        resp = session.get(base_url + "/", verify=False, timeout=timeout, allow_redirects=False)
    except Exception:
        return findings

    if resp.status_code == 401:
        www_auth = resp.headers.get("WWW-Authenticate", "")
        if "basic" in www_auth.lower():
            # Determine if the connection is unencrypted — more severe if HTTP
            scheme = "HTTP" if base_url.startswith("http://") else "HTTPS"
            severity = "MEDIUM" if scheme == "HTTP" else "INFO"
            findings.append(WebFinding(
                finding_id="WEB-BASICAUTH-INFO",
                title=f"HTTP Basic Authentication endpoint detected ({scheme})",
                description=(
                    f"The endpoint {base_url} challenges clients with HTTP Basic "
                    f"Authentication over {scheme}.  "
                    + (
                        "Credentials are base64-encoded but not encrypted over plain HTTP."
                        if scheme == "HTTP"
                        else "Basic Auth over HTTPS is acceptable but weaker than token-based auth."
                    )
                ),
                severity=severity,
                confidence=0.9,
                target_url=base_url,
                evidence=[
                    f"HTTP 401 from {base_url}/",
                    f"WWW-Authenticate: {REDACTED}",  # redact realm details
                ],
                remediation=(
                    "Use HTTPS for all Basic Auth endpoints.  "
                    "Consider migrating to token-based or OAuth2 authentication."
                ),
            ))
    return findings


def _check_cache_control(
    base_url: str,
    session: Any,
    timeout: float,
) -> List[WebFinding]:
    """Heuristic check for missing cache-control on potentially sensitive pages."""
    findings: List[WebFinding] = []
    sensitive_paths = ["/login", "/account", "/profile", "/admin", "/dashboard"]
    for path in sensitive_paths[:3]:  # conservative — check a few
        url = base_url + path
        try:
            resp = session.get(url, verify=False, timeout=timeout, allow_redirects=True)
        except Exception:
            continue
        if resp.status_code not in (200, 301, 302):
            continue
        cc = resp.headers.get("Cache-Control", "")
        pragma = resp.headers.get("Pragma", "")
        if not cc and not pragma:
            findings.append(WebFinding(
                finding_id="WEB-CACHE-MISSING",
                title=f"No Cache-Control header on potentially sensitive path {path}",
                description=(
                    f"The path {url} returns a response without Cache-Control or "
                    "Pragma headers.  If the page contains sensitive data, it may be "
                    "cached by intermediate proxies or the browser."
                ),
                severity="LOW",
                confidence=0.5,
                target_url=url,
                evidence=[
                    f"HTTP {resp.status_code} from {url}",
                    "Cache-Control: (absent)",
                    "Pragma: (absent)",
                ],
                remediation=(
                    "Add 'Cache-Control: no-store, no-cache' and 'Pragma: no-cache' "
                    "to responses containing sensitive user data."
                ),
            ))
    return findings


# ---------------------------------------------------------------------------
# Target scanning
# ---------------------------------------------------------------------------

_CHECKS = [
    _check_security_headers,
    _check_cookie_flags,
    _check_http_to_https_redirect,
    _check_cors,
    _check_directory_listing,
    _check_robots_sitemap,
    _check_server_banner,
    _check_basic_auth,
    _check_cache_control,
]


def _scan_target(
    url: str,
    user_agent: str = DEFAULT_USER_AGENT,
    timeout: float = DEFAULT_TIMEOUT,
    max_paths: int = 3,
) -> WebTargetResult:
    """Run all web checks against a single URL.  Returns a WebTargetResult."""
    result = WebTargetResult(url=url)
    if not _HAS_REQUESTS:
        result.error = "requests library not available"
        return result

    session = _make_session(user_agent, timeout)
    try:
        # Quick connectivity check
        session.get(url + "/", verify=False, timeout=timeout, allow_redirects=True)
    except Exception as exc:
        result.error = f"connection failed: {type(exc).__name__}: {str(exc)[:120]}"
        return result

    for check_fn in _CHECKS:
        try:
            if check_fn is _check_directory_listing:
                new_findings = check_fn(url, session, timeout, max_paths)
            else:
                new_findings = check_fn(url, session, timeout)
            result.findings.extend(new_findings)
        except Exception:
            pass  # individual check failures must not abort the whole target

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class WebScanner:
    """Safe, non-exploit web application scanner.

    Parameters
    ----------
    scan_results:
        The ``HybridScanner.results`` dict from an earlier scan phase.  Used to
        discover HTTP/HTTPS targets from open ports and inventory.
    extra_urls:
        Additional user-supplied URLs (from ``--url`` / ``--urls-file``).
    allow_non_inventory:
        When *False* (default) only targets derived from the scan inventory
        are scanned; ``extra_urls`` are filtered against this rule unless
        ``allow_non_inventory=True``.
    user_agent:
        Custom User-Agent string.
    timeout:
        Per-request HTTP timeout in seconds.
    concurrency:
        Maximum concurrent target workers.
    max_paths:
        Maximum number of paths to probe for directory listing checks.
    """

    def __init__(
        self,
        scan_results: Dict,
        extra_urls: Optional[List[str]] = None,
        allow_non_inventory: bool = False,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: float = DEFAULT_TIMEOUT,
        concurrency: int = DEFAULT_CONCURRENCY,
        max_paths: int = 3,
    ) -> None:
        self.scan_results = scan_results
        self.extra_urls = extra_urls or []
        self.allow_non_inventory = allow_non_inventory
        self.user_agent = user_agent
        self.timeout = timeout
        self.concurrency = concurrency
        self.max_paths = max_paths

    def _collect_targets(self) -> List[str]:
        """Build the deduplicated list of URLs to scan."""
        from_scan = _build_targets_from_scan(self.scan_results)
        if self.allow_non_inventory:
            all_raw = from_scan + self.extra_urls
        else:
            # Restrict extra URLs to those whose host matches the scan target.
            scan_target = self.scan_results.get("target", "")
            filtered_extra: List[str] = []
            for raw in self.extra_urls:
                canonical = canonicalize_url(raw)
                if canonical is None:
                    continue
                parsed = urllib.parse.urlparse(canonical)
                host = parsed.hostname or ""
                # Resolve scan_target to handle IP vs hostname equivalence
                if host == scan_target or _hosts_match(host, scan_target):
                    filtered_extra.append(canonical)
            all_raw = from_scan + filtered_extra
        return dedupe_urls(all_raw)

    def run(self) -> WebPostureReport:
        """Execute all web checks and return a WebPostureReport."""
        targets = self._collect_targets()
        report = WebPostureReport()
        if not targets:
            return report

        if not _HAS_REQUESTS:
            # Return a report with error for each target
            for url in targets:
                result = WebTargetResult(url=url, error="requests library not available")
                report.targets.append(result)
            return report

        workers = min(self.concurrency, len(targets))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_url = {
                pool.submit(
                    _scan_target,
                    url,
                    self.user_agent,
                    self.timeout,
                    self.max_paths,
                ): url
                for url in targets
            }
            for future in as_completed(future_to_url):
                try:
                    result = future.result()
                except Exception as exc:
                    url = future_to_url[future]
                    result = WebTargetResult(
                        url=url,
                        error=f"unexpected error: {type(exc).__name__}: {str(exc)[:120]}",
                    )
                report.targets.append(result)

        # Sort for deterministic output
        report.targets.sort(key=lambda t: t.url)
        return report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hosts_match(host_a: str, host_b: str) -> bool:
    """Return True when two host strings resolve to the same IP address."""
    try:
        ip_a = socket.gethostbyname(host_a)
        ip_b = socket.gethostbyname(host_b)
        return ip_a == ip_b
    except Exception:
        return False


def load_urls_file(path: str) -> List[str]:
    """Read URLs from a text file (one per line, # comments ignored)."""
    urls: List[str] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    except OSError:
        pass
    return urls
