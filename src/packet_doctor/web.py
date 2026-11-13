"""Local upload page. Binds to 127.0.0.1 only; uploads are deleted after analysis.

Hardening for a page that only ever runs on the user's own machine:
  * every template is HTML-escaped (Flask only auto-escapes *.html by default);
  * requests must carry a localhost Host header (blocks DNS-rebinding);
  * uploads must come from this page (Origin check + per-process CSRF token),
    so another website open in the browser cannot post files to it.
"""
from __future__ import annotations

import hmac
import os
import secrets
import tempfile

from flask import Flask, Response, abort, render_template, request
from jinja2 import select_autoescape

from .analyse import analyse
from .reader import PCAP_MAGICS, PCAPNG_MAGIC, CaptureError
from .report import render_html

LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


def create_app(max_upload_mb: int = 200) -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.config["MAX_CONTENT_LENGTH"] = max_upload_mb * 1024 * 1024
    app.jinja_env.autoescape = select_autoescape(["html", "j2"], default=True)
    token = secrets.token_urlsafe(24)

    def page(error: str | None = None, status: int = 200):
        from .judge import find_tshark
        return render_template("upload.html.j2", error=error, max_mb=max_upload_mb,
                               tshark=bool(find_tshark()), token=token), status

    @app.before_request
    def local_only():
        host = (request.host or "").rsplit(":", 1)[0] if not (request.host or "").startswith("[") \
            else (request.host or "").split("]")[0] + "]"
        if host not in LOCAL_HOSTS:
            abort(403)
        if request.method == "POST":
            origin = request.headers.get("Origin")
            if origin and origin.split("://", 1)[-1].rsplit(":", 1)[0] not in LOCAL_HOSTS:
                abort(403)

    @app.get("/")
    def index():
        return page()

    @app.post("/analyse")
    def do_analyse():
        if not hmac.compare_digest(request.form.get("token", ""), token):
            return page("The form has expired. Reload the page and try again.", 403)
        f = request.files.get("capture")
        if f is None or not f.filename:
            return page("Choose a .pcap or .pcapng file first.", 400)
        head = f.stream.read(4)
        f.stream.seek(0)
        if head not in PCAP_MAGICS and head != PCAPNG_MAGIC:
            return page(f"“{f.filename}” is not a pcap/pcapng capture. In Wireshark use File > Save As and "
                        "pick pcapng.", 400)
        fd, tmp = tempfile.mkstemp(suffix=".pcapng" if head == PCAPNG_MAGIC else ".pcap", prefix="pd-")
        os.close(fd)
        try:
            f.save(tmp)
            result = analyse(tmp)
            result["capture"]["file"] = os.path.basename(f.filename)
            j = None
            if request.form.get("judge"):
                from .judge import judge
                j = judge(tmp, result=result)
                if not j.get("available"):
                    j = None
            html = render_html(result, j)
        except CaptureError as exc:
            return page(str(exc), 400)
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
        return Response(html, mimetype="text/html")

    @app.errorhandler(413)
    def too_big(_e):
        return page(f"That file is larger than the {max_upload_mb} MB upload limit. Use the command line "
                    "(`packet-doctor analyse file.pcapng`) for big captures, or start the page with "
                    "--max-upload-mb.", 413)

    return app
