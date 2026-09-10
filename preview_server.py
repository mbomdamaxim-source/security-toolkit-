"""Local-only server for the browser preview, Word-report downloads, and a
fresh project archive built from the live workspace on every request."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
import zipfile

from modules.scanner.logic import build_report
from modules.scanner.report import export_scan_docx
from modules.subnet.report import export_vlsm_docx

MAX_ROWS = 100
MAX_TEXT_LENGTH = 200
REQUIRED_FIELDS = {"name", "requested_hosts", "network", "cidr", "usable_range", "broadcast"}
REPORT_TTL_SECONDS = 300
REPORTS: dict[str, tuple[float, bytes]] = {}

PROJECT_ROOT = Path(__file__).resolve().parent
_ZIP_EXCLUDE_DIRS = {".venv", ".git", "__pycache__", ".pytest_cache", "build", "dist"}
_ZIP_EXCLUDE_EXT = {".pyc"}
_ZIP_EXCLUDE_FILES = {"Bastion-source.zip", "Bastion-windows.zip"}
# Inside the archive everything lives under this folder so extraction mirrors
# the original project structure exactly.
_ZIP_ROOT_FOLDER = "security-toolkit-"


def build_project_zip() -> bytes:
    """Zip the current workspace (always fresh) into an in-memory archive.

    The archive is rebuilt on every request, so it automatically contains
    every update as soon as a file changes - no stale copies."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for dirpath, dirnames, filenames in os.walk(PROJECT_ROOT):
            dirnames[:] = [name for name in dirnames if name not in _ZIP_EXCLUDE_DIRS]
            for filename in sorted(filenames):
                if filename in _ZIP_EXCLUDE_FILES:
                    continue
                if Path(filename).suffix in _ZIP_EXCLUDE_EXT:
                    continue
                full = Path(dirpath) / filename
                relative = full.relative_to(PROJECT_ROOT)
                archive.write(full, _ZIP_ROOT_FOLDER / relative)
    return buffer.getvalue()

class PreviewHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(302)
            self.send_header("Location", "/ui_preview.html")
            self.end_headers()
            return
        if self.path == "/download-project":
            try:
                document = build_project_zip()
            except Exception:
                self.send_error(500, "Could not build the project archive")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="Bastion-source.zip"')
            self.send_header("Content-Length", str(len(document)))
            self.end_headers()
            self.wfile.write(document)
            return
        if self.path.startswith(("/download-vlsm/", "/download-scan/")):
            token = self.path.rsplit("/", 1)[-1]
            created, document = REPORTS.pop(token, (0.0, b""))
            if not document or time.monotonic() - created > REPORT_TTL_SECONDS:
                self.send_error(404, "Report is no longer available")
                return
            filename = "Scan_Report.docx" if self.path.startswith("/download-scan/") else "VLSM_Allocation_Report.docx"
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(document)))
            self.end_headers()
            self.wfile.write(document)
            return
        if self.path == "/ui_preview.html":
            super().do_GET()
            return
        # This local preview server is bound to 0.0.0.0. Serve nothing else:
        # never expose the repository, its .git directory, or source files.
        self.send_error(404, "Not found")

    def do_POST(self):
        if self.path == "/export-scan":
            # The preview posts the same raw scan payload that is displayed
            # on the page, so the exported report always matches the view.
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 500_000:
                    raise ValueError
                payload = json.loads(self.rfile.read(size))
                if not isinstance(payload, dict):
                    raise ValueError
                with tempfile.TemporaryDirectory() as directory:
                    report = build_report(payload)
                    report_path = export_scan_docx(Path(directory) / "Scan_Report.docx", report)
                    document = report_path.read_bytes()
            except (ValueError, OSError, json.JSONDecodeError):
                self.send_error(400, "Invalid report data")
                return
            token = secrets.token_urlsafe(24)
            REPORTS[token] = (time.monotonic(), document)
            response = json.dumps({"download_url": f"/download-scan/{token}"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            return
        if self.path != "/export-vlsm":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 100_000:
                raise ValueError
            body = self.rfile.read(size)
            if self.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
                from urllib.parse import parse_qs
                payload = json.loads(parse_qs(body.decode("utf-8"), strict_parsing=True)["payload"][0])
            else:
                payload = json.loads(body)
            base_network = payload["base_network"]
            rows = payload["allocations"]
            if not isinstance(base_network, str) or len(base_network) > MAX_TEXT_LENGTH or not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ROWS:
                raise ValueError
            for row in rows:
                if not isinstance(row, dict) or set(row) != REQUIRED_FIELDS or not isinstance(row["requested_hosts"], int) or row["requested_hosts"] < 1:
                    raise ValueError
                if any(not isinstance(row[field], str) or len(row[field]) > MAX_TEXT_LENGTH for field in REQUIRED_FIELDS - {"requested_hosts"}):
                    raise ValueError
            with tempfile.TemporaryDirectory() as directory:
                report_path = export_vlsm_docx(Path(directory) / "VLSM_Allocation_Report.docx", base_network, rows)
                document = report_path.read_bytes()
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            self.send_error(400, "Invalid report data")
            return
        expired = [token for token, (created, _) in REPORTS.items() if time.monotonic() - created > REPORT_TTL_SECONDS]
        for token in expired:
            REPORTS.pop(token, None)
        token = secrets.token_urlsafe(24)
        REPORTS[token] = (time.monotonic(), document)
        response = json.dumps({"download_url": f"/download-vlsm/{token}"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), PreviewHandler).serve_forever()
