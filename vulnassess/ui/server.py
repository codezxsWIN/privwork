"""Loopback workbench with explicit analyst requests and a scoped report import."""

import json
import os
import re
import time
from dataclasses import dataclass
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
from socketserver import TCPServer
from threading import Lock
from typing import Any, Callable, cast
from urllib.parse import parse_qs, unquote, urlsplit

import yaml

import vulnassess.analyst as analyst
import vulnassess.live_assessment as live_assessment
import vulnassess.orchestrator as orchestrator
from vulnassess.errors import AdapterError, ConfigError, LLMUnavailable, NeedsReview, ScopeError
from vulnassess.nessus_import import import_nessus_report
from vulnassess.readers._input import MAX_CAPTURE_BYTES
from vulnassess.repository import ENV_VAR, AssessmentRepository
from vulnassess.settings import CONFIG_FILES, Settings
from vulnassess.target_intake import resolve_addresses
from vulnassess.ui.entry import render_entry
from vulnassess.ui.reader import local_path, open_read_store

STATIC_ROOT = Path(__file__).resolve().parent / "static"
# data: images carry Cobe's embedded land-map texture; without it the globe has no continents.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'none'"
)
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".woff2": "font/woff2",
}
MAX_STATIC_BYTES = 4 * 1024 * 1024
LAB_REFERENCES = {
    "owasp.org": "OWASP project page (Juice Shop or WebGoat)",
    "www.owasp.org": "OWASP project page (Juice Shop or WebGoat)",
    "dvwa.co.uk": "DVWA project page",
    "www.dvwa.co.uk": "DVWA project page",
    "docs.rapid7.com": "Metasploitable documentation",
    "tryhackme.com": "TryHackMe platform",
    "www.tryhackme.com": "TryHackMe platform",
    "hackthebox.com": "Hack The Box platform",
    "www.hackthebox.com": "Hack The Box platform",
    "portswigger.net": "PortSwigger Web Security Academy",
    "overthewire.org": "OverTheWire wargames",
    "www.overthewire.org": "OverTheWire wargames",
    "picoctf.org": "picoCTF platform",
    "www.picoctf.org": "picoCTF platform",
    "google-gruyere.appspot.com": "Google Gruyere training platform",
}


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    content_type: str = "application/json; charset=utf-8"


def json_response(status: int, payload: Any) -> Response:
    return Response(status, json.dumps(payload, sort_keys=True, allow_nan=False).encode("utf-8"))


def error_response(status: int, message: str) -> Response:
    return json_response(
        status,
        {
            "error": {
                "type": "ConfigError",
                "message": message,
                "exit_code": ConfigError.exit_code,
            },
        },
    )


class UiApplication:
    def __init__(
        self,
        database: str | Path,
        config_dir: str | Path,
        run_id: str | None = None,
        analyst_model: str = analyst.DEFAULT_MODEL,
        ollama_host: str = analyst.DEFAULT_HOST,
    ) -> None:
        resolved = str(database)
        if os.environ.get(ENV_VAR) and not resolved.startswith(
            ("postgres://", "postgresql://", "env:")
        ):
            # The backend-only env var takes precedence over the default SQLite
            # path so the same server can read the Supabase cloud store.
            resolved = f"env:{ENV_VAR}"
        self.database = (
            resolved
            if resolved.startswith(("postgres://", "postgresql://", "env:"))
            else local_path(resolved)
        )
        self.config_dir = local_path(config_dir)
        self.run_id = run_id
        self.analyst_model = analyst_model
        self.ollama_host = ollama_host
        self._live_lock = Lock()
        self._last_live_scan: dict[str, float] = {}
        self._recent_live_cases: dict[str, tuple[float, dict[str, Any]]] = {}
        for name in CONFIG_FILES:
            path = local_path(self.config_dir / name)
            if not path.is_relative_to(self.config_dir):
                raise ConfigError(f"configuration file leaves its local directory: {path}")
        settings = Settings(self.config_dir)
        self.configurations: dict[str, dict[str, Any]] = {}
        for name in ("scope", "weights"):
            path = self.config_dir / f"{name}.yaml"
            try:
                content = path.read_bytes()
                document = content.decode("utf-8")
                values = yaml.safe_load(document)
            except (OSError, UnicodeError, yaml.YAMLError) as error:
                raise ConfigError(f"cannot read configuration file {path}") from error
            if values != settings.raw[path.name]:
                raise ConfigError(f"configuration file changed during validation: {path}")
            self.configurations[name] = {
                "path": str(path),
                "sha256": sha256(content).hexdigest(),
                "values": values,
                "yaml": document,
            }
        with open_read_store(self.database) as store:
            if run_id is None:
                store.runs()
            else:
                store.run_info(run_id)
        if not (STATIC_ROOT / "index.html").is_file():
            raise ConfigError(f"MISSING: UI entry point {STATIC_ROOT / 'index.html'}")

    def _static(self, parts: list[str]) -> Response:
        path = STATIC_ROOT.joinpath(*parts).resolve()
        if not path.is_relative_to(STATIC_ROOT) or path.suffix not in CONTENT_TYPES:
            return error_response(404, "UI static file not found")
        try:
            if not path.is_file() or path.stat().st_size > MAX_STATIC_BYTES:
                return error_response(404, "UI static file not found")
            return Response(200, path.read_bytes(), CONTENT_TYPES[path.suffix])
        except OSError:
            return error_response(404, "UI static file not found")

    def _entry(self, requested_run: str | None = None) -> Response:
        template = self._static(["index.html"])
        if template.status != 200:
            return template
        try:
            with open_read_store(self.database) as store:
                run_id = self.run_id if requested_run is None else requested_run
                payload = None if run_id is None else store.run(run_id)
                runs = store.runs() if payload is None else []
            document = render_entry(
                template.body.decode("utf-8"), payload, runs, self.configurations
            )
        except ConfigError as error:
            return error_response(409, str(error))
        return Response(200, document.encode("utf-8"), "text/html; charset=utf-8")

    def cvss_fixture(self) -> dict[str, Any]:
        path = (
            Path(__file__).resolve().parents[2]
            / "tests"
            / "synthetic"
            / "synthetic_cvss31_vectors.json"
        )
        if not path.is_file():
            raise ConfigError(f"MISSING: CVSS arithmetic fixture {path}")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ConfigError(f"cannot read CVSS arithmetic fixture {path}") from error

    def target_check(self, target: str) -> dict[str, Any]:
        """Classify an IP, lab URL, or project link; never connect to the target."""
        submitted = target.strip()
        if not submitted or len(submitted) > 512:
            raise ConfigError("Enter one target address of at most 512 characters")
        try:
            parsed = urlsplit(submitted if "://" in submitted else f"//{submitted}")
        except ValueError as error:
            raise ConfigError("Target URL has an invalid host") from error
        if (
            (parsed.scheme and parsed.scheme not in ("http", "https"))
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ConfigError("Target URL must be HTTP(S), without credentials, query or fragment")
        try:
            hostname = parsed.hostname
            port = parsed.port
        except ValueError as error:
            raise ConfigError("Target URL has an invalid host or port") from error
        if not hostname or (port is not None and port < 1):
            raise ConfigError("Target URL needs a valid host")
        hostname = hostname.rstrip(".").lower()
        if hostname in LAB_REFERENCES:
            return {
                "submitted": submitted,
                "status": "reference",
                "reason": f"{LAB_REFERENCES[hostname]} — not a scan target. Run or open your assigned lab instance and check its specific URL/IP.",
            }
        try:
            addresses = [str(ip_address(hostname))]
        except ValueError:
            if len(hostname) > 253 or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", hostname):
                raise ConfigError("Enter an IP or valid domain, not a CIDR or project title")
            try:
                addresses = resolve_addresses(hostname, port or 0)
            except (OSError, ValueError) as error:
                raise ConfigError("Domain could not be resolved; no scan was started") from error
            if not addresses or len(addresses) > 32:
                raise ConfigError("Domain resolution returned no usable or too many addresses")
        settings = Settings(self.config_dir)
        if any(settings.scope.is_canary(address) for address in addresses):
            return {
                "submitted": submitted,
                "status": "blocked",
                "reason": "Canary address: never scan",
            }
        if any(not settings.scope.contains(address) for address in addresses):
            return {
                "submitted": submitted,
                "status": "blocked",
                "resolved_ips": addresses,
                "reason": "At least one resolved address is outside the authorised scope; no scanner command was built",
            }
        missing = [] if live_assessment.nmap_binary() else ["nmap"]
        return {
            "target": addresses[0],
            "submitted": submitted,
            "resolved_ips": addresses,
            "status": "needs-pinning"
            if hostname != addresses[0]
            else ("ready" if not missing else "needs-tools"),
            "scope": settings.scope.segment(addresses[0]) or addresses[0],
            "missing": missing,
            "reason": (
                "Scope accepted. A live run will pin this domain to its authorised IP."
                if hostname != addresses[0]
                else (
                    "Scope accepted for a light live Nmap scan."
                    if not missing
                    else "Scope accepted, but Nmap is unavailable."
                )
            ),
        }

    def analyst_report(
        self,
        run_id: str,
        host_ip: str,
        on_progress: Callable[[str, str, str], None] | None = None,
        provider: str = "ollama",
    ) -> dict[str, Any]:
        if on_progress is not None:
            on_progress("records", "running", "Reading the selected stored assessment")
        with open_read_store(self.database) as store:
            payload = store.run(run_id)
        if on_progress is not None:
            on_progress("records", "complete", "Stored assessment loaded")
        return {
            "run_id": run_id,
            **analyst.analyze_target(
                payload,
                host_ip,
                model=self.analyst_model,
                ollama_host=self.ollama_host,
                provider=provider,
                on_progress=on_progress,
            ),
        }

    def live_report(
        self,
        target: str,
        provider: str,
        on_progress: Callable[[str, str, str], None],
        on_capture: Callable[[dict[str, Any]], None] | None = None,
        *,
        reuse_recent: bool = False,
    ) -> dict[str, Any]:
        on_progress("scope", "running", "Resolving and checking the entered target")
        check = self.target_check(target)
        addresses = check.get("resolved_ips") or []
        if (
            check.get("status") not in ("ready", "needs-tools", "needs-pinning")
            or len(addresses) != 1
        ):
            raise ConfigError(
                check.get("reason") or "Target must resolve to one authorised address"
            )
        if check.get("missing"):
            raise ConfigError("Nmap is unavailable; configure VULNASSESS_NMAP_BIN or install Nmap")
        target_ip = addresses[0]
        with self._live_lock:
            now = time.monotonic()
            recent = self._recent_live_cases.get(target_ip)
            case = recent[1] if recent and now - recent[0] < 600 else None
            if case is not None and not reuse_recent:
                raise ConfigError(
                    "This target was scanned in the last 10 minutes. Choose re-analyze recent evidence, or wait before a new Nmap scan."
                )
            if case is None and reuse_recent:
                raise ConfigError(
                    "No recent scan is available to re-analyze; choose a new Nmap scan."
                )
            if case is None:
                previous = self._last_live_scan.get(target_ip, 0.0)
                if previous and now - previous < 600:
                    raise ConfigError(
                        "A scan of this target is already running or its evidence is unavailable; wait 10 minutes before another live scan"
                    )
                self._last_live_scan[target_ip] = now
        if case is not None:
            on_progress("scope", "complete", f"{target} pinned to authorised {target_ip}")
            on_progress(
                "scanner", "complete", "Reused the recent live scan; Nmap was not run again"
            )
            if on_capture is not None:
                on_capture(
                    {
                        key: case[key]
                        for key in (
                            "target",
                            "resolved_ip",
                            "services",
                            "finding_count",
                            "decision_frame",
                        )
                        if key in case
                    }
                )
            on_progress("context", "complete", "Reused context from the recent live scan")
            result = analyst.analyze_target(
                case["payload"], target_ip, provider=provider, on_progress=on_progress
            )
            return {key: value for key, value in case.items() if key != "payload"} | {
                "analyst": result,
                "reused_scan": True,
            }

        def remember_case(scanned: dict[str, Any]) -> None:
            with self._live_lock:
                self._recent_live_cases[target_ip] = (time.monotonic(), scanned)

        return live_assessment.run(
            target,
            check,
            self.config_dir,
            provider=provider,
            on_progress=on_progress,
            on_capture=on_capture,
            on_case=remember_case,
        )

    def import_nessus_report(
        self, run_id: str, target_ip: str, content: bytes, *, new_run: bool = False
    ) -> dict[str, Any]:
        """Import one completed export into an existing local run, then update its analysis."""
        return import_nessus_report(
            self.database, self.config_dir, run_id, target_ip, content, new_run=new_run
        )

    def _repository(self) -> AssessmentRepository:
        """Open the expanded assessment store strictly read-only."""
        value = self.database if isinstance(self.database, str) else str(self.database)
        return AssessmentRepository(value, read_only=True)

    def _assessment_api(self, parts: list[str], query: dict[str, list[str]]) -> Response | None:
        """Read-only assessment-store routes; the browser never sees the DB URL."""
        if tuple(parts) in (
            ("api", "assessment-runs"),
            ("api", "assets"),
            ("api", "model-evaluations"),
            ("api", "ablations"),
        ):
            with self._repository() as repo:
                if parts == ["api", "assessment-runs"]:
                    payload: Any = {"runs": repo.assessment_runs()}
                elif parts == ["api", "assets"]:
                    payload = {"assets": repo.asset_inventory(self._first(query, "run"))}
                elif parts == ["api", "model-evaluations"]:
                    payload = repo.model_evaluations()
                else:
                    payload = {"ablations": repo.ablation_summaries()}
            return json_response(200, payload)
        if parts == ["api", "findings"]:
            try:
                limit = int(self._first(query, "limit") or 200)
            except ValueError:
                limit = 200
            with self._repository() as repo:
                findings = repo.findings_queue(
                    run_id=self._first(query, "run"),
                    status=self._first(query, "status"),
                    severity=self._first(query, "severity"),
                    decision=self._first(query, "decision"),
                    limit=limit,
                )
            return json_response(200, {"findings": findings})
        if len(parts) == 3 and parts[1] == "asset":
            with self._repository() as repo:
                return json_response(200, repo.asset_details(parts[2]))
        if len(parts) == 3 and parts[1] == "finding":
            with self._repository() as repo:
                return json_response(200, repo.finding_evidence(parts[2]))
        if len(parts) == 4 and parts[1] == "finding" and parts[3] == "score-history":
            with self._repository() as repo:
                return json_response(200, repo.finding_score_history(parts[2]))
        return None

    @staticmethod
    def _first(query: dict[str, list[str]], name: str) -> str | None:
        values = query.get(name)
        return values[0] if values else None

    def get(self, target: str) -> Response:
        try:
            parsed = urlsplit(target)
            decoded = unquote(parsed.path, errors="strict")
        except (ValueError, UnicodeError):
            return error_response(404, "UI path not found")
        if (
            parsed.scheme
            or parsed.netloc
            or parsed.fragment
            or not decoded.startswith("/")
            or any(ord(character) < 32 or ord(character) == 127 for character in decoded)
            or any(character in decoded for character in ("\\", ":", "%"))
        ):
            return error_response(404, "UI path not found")
        if decoded == "/workflow":
            return self._static(["workflow.html"])
        if decoded == "/":
            parameters = parse_qs(parsed.query, keep_blank_values=True)
            if parameters:
                if (
                    set(parameters) != {"run"}
                    or len(parameters["run"]) != 1
                    or not parameters["run"][0]
                ):
                    return error_response(400, "Entry query accepts exactly one non-empty run")
                return self._entry(parameters["run"][0])
            return self._entry()
        parts = decoded[1:].split("/")
        if any(not part or part.startswith(".") for part in parts):
            return error_response(404, "UI path not found")
        if parts == ["static", "index.html"]:
            return self._entry()
        if parts[0] == "static":
            return self._static(parts[1:])
        if parts in (["api", "scope"], ["api", "weights"]):
            return json_response(200, self.configurations[parts[1]])
        if parts == ["api", "cvss-fixture"]:
            try:
                return json_response(200, self.cvss_fixture())
            except ConfigError as error:
                return error_response(409, str(error))
        if parts == ["api", "target-check"]:
            parameters = parse_qs(parsed.query, keep_blank_values=True)
            if set(parameters) != {"target"} or len(parameters["target"]) != 1:
                return error_response(400, "Target check requires exactly one target")
            try:
                return json_response(200, self.target_check(parameters["target"][0]))
            except ConfigError as error:
                return error_response(400, str(error))
        if parts == ["api", "scanner-status"]:
            return json_response(
                200,
                {
                    "nikto": orchestrator.scanner_status("nikto"),
                    "nessus": {
                        "status": "import-only",
                        "detail": "Completed .nessus XML scan exports can be imported for an authorized target; the app does not launch Nessus.",
                    },
                },
            )
        if parts[0] != "api":
            return error_response(404, "UI route not found")
        try:
            if len(parts) == 4 and parts[1] == "analyst":
                return json_response(200, self.analyst_report(parts[2], parts[3]))
            assessment = self._assessment_api(parts, parse_qs(parsed.query, keep_blank_values=True))
            if assessment is not None:
                return assessment
            with open_read_store(self.database) as store:
                if parts == ["api", "runs"]:
                    return json_response(200, {"runs": store.runs(), "selected_run": self.run_id})
                if len(parts) == 3 and parts[1] == "run":
                    return json_response(200, store.run(parts[2]))
                if len(parts) == 3 and parts[1] == "eval":
                    store.run_info(parts[2])
                    return json_response(
                        409,
                        {
                            "run_id": parts[2],
                            **store.unavailable("evaluation result", parts[2]),
                        },
                    )
                if len(parts) == 4 and parts[1] == "diff":
                    store.run_info(parts[2])
                    store.run_info(parts[3])
                    return json_response(
                        409,
                        {
                            "run_ids": parts[2:],
                            **store.unavailable("diff result", f"{parts[2]} / {parts[3]}"),
                        },
                    )
        except NeedsReview as error:
            return error_response(422, str(error))
        except (ConfigError, LLMUnavailable) as error:
            return error_response(409, str(error))
        return error_response(404, "UI route not found")


class UiRequestHandler(BaseHTTPRequestHandler):
    server_version = "VulnAssess"
    sys_version = ""
    timeout = 5.0

    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _reply(self, response: Response) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if response.status == 405:
            self.send_header("Allow", "GET")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self._reply(error_response(code, message or "Invalid UI request"))

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        if self.command not in ("GET", "POST"):
            self.close_connection = True
            self._reply(error_response(405, "UI supports GET only"))
            return False
        return True

    def _same_origin(self) -> bool:
        server = cast(UiServer, self.server)
        authority = f"127.0.0.1:{server.server_address[1]}"
        if self.headers.get_all("Host", []) != [authority]:
            self._reply(error_response(403, "UI Host must match its loopback address and port"))
            return False
        origin = self.headers.get("Origin")
        allowed = (None, f"http://{authority}")
        if origin not in allowed or self.headers.get("Sec-Fetch-Site") == "cross-site":
            self._reply(error_response(403, "Cross-origin UI requests are refused"))
            return False
        return True

    def _stream_analyst(self, run_id: str, host_ip: str, provider: str = "ollama") -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        def send(event: dict[str, Any]) -> None:
            self.wfile.write(
                json.dumps(event, ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n"
            )
            self.wfile.flush()

        try:
            server = cast(UiServer, self.server)
            result = server.application.analyst_report(
                run_id,
                host_ip,
                provider=provider,
                on_progress=lambda stage, state, detail: send(
                    {"type": "stage", "stage": stage, "state": state, "detail": detail}
                ),
            )
            send({"type": "result", "result": result})
        except (BrokenPipeError, ConnectionResetError):
            return
        except NeedsReview as error:
            try:
                send({"type": "needs-review", "message": str(error)})
            except (BrokenPipeError, ConnectionResetError):
                return
        except (ConfigError, LLMUnavailable) as error:
            try:
                send({"type": "error", "message": str(error)})
            except (BrokenPipeError, ConnectionResetError):
                return
        except Exception:
            try:
                send({"type": "error", "message": "Analyst request failed unexpectedly."})
            except (BrokenPipeError, ConnectionResetError):
                return

    def _stream_live(self, target: str, provider: str, reuse_recent: bool = False) -> None:
        self.send_response(200)
        for name, value in (
            ("Content-Type", "application/x-ndjson; charset=utf-8"),
            ("Content-Security-Policy", CSP),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Cache-Control", "no-store"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("Connection", "close"),
        ):
            self.send_header(name, value)
        self.end_headers()
        self.close_connection = True

        def send(event: dict[str, Any]) -> None:
            self.wfile.write(
                json.dumps(event, ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n"
            )
            self.wfile.flush()

        try:
            server = cast(UiServer, self.server)
            result = server.application.live_report(
                target,
                provider,
                lambda stage, state, detail: send(
                    {"type": "stage", "stage": stage, "state": state, "detail": detail}
                ),
                lambda capture: send({"type": "scan", "scan": capture}),
                reuse_recent=reuse_recent,
            )
            send({"type": "result", "result": result})
        except (BrokenPipeError, ConnectionResetError):
            return
        except NeedsReview as error:
            try:
                send({"type": "needs-review", "message": str(error)})
            except (BrokenPipeError, ConnectionResetError):
                return
        except (ConfigError, LLMUnavailable) as error:
            try:
                send({"type": "error", "message": str(error)})
            except (BrokenPipeError, ConnectionResetError):
                return
        except Exception:
            try:
                send({"type": "error", "message": "Live assessment failed unexpectedly."})
            except (BrokenPipeError, ConnectionResetError):
                return

    def do_GET(self) -> None:
        if not self._same_origin():
            return
        server = cast(UiServer, self.server)
        try:
            parsed = urlsplit(self.path)
            decoded = unquote(parsed.path, errors="strict")
        except (ValueError, UnicodeError):
            self._reply(error_response(404, "UI route not found"))
            return
        parts = decoded.split("/")
        if (
            len(parts) == 6
            and parts[:3] == ["", "api", "analyst"]
            and parts[5] == "events"
            and not parsed.scheme
            and not parsed.netloc
            and not parsed.query
            and not parsed.fragment
            and all(parts[3:5])
            and not any(part.startswith(".") for part in parts[3:5])
            and not any(character in decoded for character in ("\\", ":", "%"))
            and not any(ord(character) < 32 or ord(character) == 127 for character in decoded)
        ):
            self._stream_analyst(parts[3], parts[4])
            return
        self._reply(server.application.get(self.path))

    def do_POST(self) -> None:
        server = cast(UiServer, self.server)
        if (
            self.path != "/api/live-assessment/events"
            and self.path != "/api/nessus-import"
            and not self.path.startswith("/api/analyst/")
        ):
            self._reply(error_response(405, "POST route not found"))
            return
        if not self._same_origin():
            return
        authority = f"127.0.0.1:{server.server_address[1]}"
        action = (
            "nessus-import"
            if self.path == "/api/nessus-import"
            else "live-assessment"
            if self.path == "/api/live-assessment/events"
            else "cloud-analyst"
        )
        if (
            self.headers.get("Origin") != f"http://{authority}"
            or self.headers.get("X-VulnAssess-Action") != action
        ):
            self._reply(error_response(403, "Explicit same-origin action required"))
            return
        if self.path == "/api/nessus-import":
            try:
                size = int(self.headers.get("Content-Length", "-1"))
                run_id = self.headers.get("X-VulnAssess-Run", "")
                target_ip = self.headers.get("X-VulnAssess-Target", "")
                new_run = self.headers.get("X-VulnAssess-New-Run", "false")
                if (
                    self.headers.get("Content-Type") != "application/xml"
                    or not 0 < size <= MAX_CAPTURE_BYTES
                    or not 0 < len(run_id) <= 128
                    or not 0 < len(target_ip) <= 45
                    or new_run not in ("true", "false")
                ):
                    raise ValueError("invalid Nessus report request")
                ip_address(target_ip)
                result = server.application.import_nessus_report(
                    run_id, target_ip, self.rfile.read(size), new_run=new_run == "true"
                )
            except (ValueError, AdapterError, ConfigError, ScopeError, OSError) as error:
                self._reply(error_response(400, str(error)))
                return
            self._reply(json_response(200, result))
            return
        try:
            size = int(self.headers.get("Content-Length", "-1"))
            if self.headers.get("Content-Type") != "application/json" or not 0 < size <= 1024:
                raise ValueError("invalid request size or type")
            body = json.loads(self.rfile.read(size))
            parsed = urlsplit(self.path)
            decoded = unquote(parsed.path, errors="strict")
            parts = decoded.split("/")
        except (ValueError, UnicodeError, json.JSONDecodeError):
            self._reply(error_response(400, "Invalid cloud analyst request"))
            return
        if self.path == "/api/live-assessment/events":
            if (
                not isinstance(body, dict)
                or set(body)
                not in (
                    {"target", "provider", "share_evidence"},
                    {"target", "provider", "share_evidence", "reuse_recent"},
                )
                or not isinstance(body["target"], str)
                or not 0 < len(body["target"]) <= 512
                or body["provider"] not in ("ollama", "openrouter", "groq")
                or body["share_evidence"] is not (body["provider"] in ("openrouter", "groq"))
                or type(body.get("reuse_recent", False)) is not bool
            ):
                self._reply(error_response(400, "Invalid live assessment request"))
                return
            self._stream_live(body["target"], body["provider"], body.get("reuse_recent", False))
            return
        if (
            not isinstance(body, dict)
            or body
            not in (
                {"provider": "openrouter", "share_evidence": True},
                {"provider": "groq", "share_evidence": True},
            )
            or len(parts) != 6
            or parts[:3] != ["", "api", "analyst"]
            or parts[5] != "events"
            or not all(parts[3:5])
            or parsed.query
            or parsed.fragment
            or parsed.scheme
            or parsed.netloc
            or any(character in decoded for character in ("\\", ":", "%"))
            or any(ord(character) < 32 or ord(character) == 127 for character in decoded)
        ):
            self._reply(error_response(400, "Invalid cloud analyst request"))
            return
        self._stream_analyst(parts[3], parts[4], provider=body["provider"])


class UiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self, application: UiApplication, port: int = 8765, host: str = "127.0.0.1"
    ) -> None:
        if host != "127.0.0.1":
            raise ConfigError(f"UI bind address {host!r} is forbidden; use 127.0.0.1")
        if type(port) is not int or not 0 <= port <= 65535:
            raise ConfigError(f"UI port must be an integer in 0..65535, got {port!r}")
        self.application = application
        try:
            super().__init__((host, port), UiRequestHandler)
        except OSError as error:
            raise ConfigError(
                f"cannot bind UI to 127.0.0.1:{port}; choose another --port ({error})"
            ) from error

    def server_bind(self) -> None:
        TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]
