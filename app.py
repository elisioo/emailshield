"""EmailShield Flask website and read-only scanning API (no account/database)."""
from __future__ import annotations
import os
from pathlib import Path
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from analyzers import analyze_email, MAX_EMAIL_BYTES, MAX_PASTE_CHARS

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=MAX_EMAIL_BYTES + 96 * 1024,
    JSON_SORT_KEYS=False,
)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    return response


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "EmailShield"})


def error(message: str, status: int = 400):
    return jsonify({"error": message}), status


@app.errorhandler(RequestEntityTooLarge)
def too_large(exc):
    return error("Upload limit exceeded. Choose an email under 2 MB.", 413)


@app.post("/api/analyze")
def analyze():
    mode = request.form.get("mode", "")
    if mode == "upload":
        attached = request.files.get("file")
        if not attached or not attached.filename:
            return error("Choose an .eml or .txt file to scan.")
        name = Path(attached.filename.replace("\\", "/")).name
        if Path(name).suffix.lower() not in {".eml", ".txt"}:
            return error("Only .eml and .txt files are accepted.")
        source = secure_filename(name)[:100] or "Uploaded email"
        content = attached.stream.read(MAX_EMAIL_BYTES + 1)
    elif mode == "paste":
        pasted = request.form.get("email_text", "")
        if len(pasted) > MAX_PASTE_CHARS:
            return error("Pasted text is too long (200,000 characters maximum).", 413)
        content = pasted.encode("utf-8")
        source = "Pasted email"
    else:
        return error("Choose a file upload or pasted email.")

    if not content or not content.strip():
        return error("Provide email content before scanning.")
    if len(content) > MAX_EMAIL_BYTES:
        return error("Email is larger than the 2 MB analysis limit.", 413)
    try:
        report = analyze_email(content, source=source)
    except ValueError as exc:
        return error(str(exc))
    return jsonify(report)


if __name__ == "__main__":
    # Never enable debug in production. Prefer a WSGI server for deployment.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
