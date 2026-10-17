"""Sentinel's custom Flask web interface. Local synthetic inputs only."""
from __future__ import annotations

import csv
import io
import json
import os
import webbrowser
from threading import Timer
from typing import Any

from flask import Flask, Response, flash, jsonify, redirect, render_template, request, url_for

from runtime import SentinelRuntime
from safe_json import parse_json_message
from samples import build_auth_lab_examples, build_demo_messages
from validator import (
    ALLOWED_COMMANDS,
    ALLOWED_ROLES,
    TELEMETRY_RANGES,
    example_schema,
)


def create_app(testing: bool = False, authenticator=None, require_auth: bool | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        TESTING=testing,
        SECRET_KEY=os.environ.get("SENTINEL_SECRET_KEY") or os.urandom(32),
        MAX_CONTENT_LENGTH=96 * 1024,
        SEND_FILE_MAX_AGE_DEFAULT=0,
    )
    runtime = SentinelRuntime(authenticator, require_auth)
    app.extensions["sentinel_runtime"] = runtime

    def make_examples() -> dict[str, dict[str, Any]]:
        messages = build_demo_messages()
        examples = {
            "Valid telemetry": messages[0],
            "Valid command": messages[1],
            "Missing required field": messages[2],
            "Stale timestamp": messages[3],
            "Unauthorized command": messages[4],
            "Out-of-range telemetry": messages[5],
            "Old sequence number": messages[6],
        }
        examples.update(build_auth_lab_examples(runtime.authenticator))
        return examples

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.get("/")
    def dashboard():
        summary = runtime.summary()
        audit = list(reversed(runtime.snapshot()))
        return render_template(
            "dashboard.html",
            active_page="dashboard",
            summary=summary,
            audit=audit[:7],
            latest_results=list(runtime.latest_results),
            auth=runtime.auth_status(),
        )

    @app.post("/demo")
    def run_demo():
        results = runtime.run_demo_batch()
        accepted = sum(row["decision"] == "ACCEPTED" for row in results)
        rejected = len(results) - accepted
        flash(f"Demo complete: {accepted} accepted, {rejected} rejected. All messages are synthetic.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/reset")
    def reset():
        runtime.reset()
        flash("Local session cleared. No audit records remain in this running process.", "info")
        return redirect(url_for("audit_log"))

    @app.route("/validate", methods=["GET", "POST"])
    def validate_message():
        examples = make_examples()
        selected = "Valid telemetry"
        raw_json = json.dumps(examples[selected], indent=2)
        result = None
        parse_error = None

        if request.method == "POST":
            raw_json = request.form.get("raw_json", "")
            selected = request.form.get("example", "Custom JSON")
            try:
                message = parse_json_message(raw_json)
                result = runtime.evaluate(message)
                auth_failed = result["authentication"] not in ("VALID", "NOT_CHECKED")
                flash(
                    "Message accepted: all configured checks passed."
                    if result["decision"] == "ACCEPTED"
                    else ("Message rejected: authentication failed." if auth_failed
                          else "Message rejected: one or more configured checks failed."),
                    "success" if result["decision"] == "ACCEPTED" else "danger",
                )
            except json.JSONDecodeError as exc:
                parse_error = f"Invalid JSON syntax: {exc.msg} (line {exc.lineno}, column {exc.colno}). No message was processed."
            except ValueError as exc:
                parse_error = f"Input rejected before validation: {exc}"

        return render_template(
            "validate.html",
            active_page="validate",
            examples=examples,
            examples_json=json.dumps(examples),
            selected=selected,
            raw_json=raw_json,
            result=result,
            parse_error=parse_error,
            auth=runtime.auth_status(),
        )

    @app.get("/schema")
    def schema():
        return render_template(
            "schema.html",
            active_page="schema",
            schema=example_schema(),
            telemetry_ranges=TELEMETRY_RANGES,
            command_roles=ALLOWED_COMMANDS,
            roles=sorted(ALLOWED_ROLES),
        )

    @app.get("/audit")
    def audit_log():
        return render_template(
            "audit.html",
            active_page="audit",
            audit=list(reversed(runtime.snapshot())),
            summary=runtime.summary(),
            auth=runtime.auth_status(),
        )

    @app.get("/audit/export.json")
    def export_json():
        payload = json.dumps(runtime.snapshot(), indent=2, ensure_ascii=False)
        return Response(
            payload,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=sentinel_audit_log.json"},
        )

    @app.get("/audit/export.csv")
    def export_csv():
        output = io.StringIO(newline="")
        fields = [
            "event_number", "message_id", "satellite_id", "message_type",
            "sequence_number", "decision", "authentication", "reason", "evaluated_at",
        ]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in runtime.snapshot():
            writer.writerow(row)
        return Response(
            output.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=sentinel_audit_log.csv"},
        )

    # ---- HMAC authentication endpoints (the secret key never leaves the server) ----
    @app.post("/auth/sign")
    def auth_sign():
        """DEMO CONVENIENCE: signs a synthetic message server-side.

        A real system would never expose a signing oracle to untrusted users. Requiring a JSON
        content type also stops a cross-site HTML form from triggering it.
        """
        if not request.is_json:
            return jsonify(ok=False, error="Send application/json."), 415
        body = request.get_json(silent=True)
        raw = body.get("raw_json") if isinstance(body, dict) else None
        try:
            message = parse_json_message(raw)
        except ValueError as exc:
            return jsonify(ok=False, error=f"Cannot sign: {exc}"), 400
        if not isinstance(message, dict):
            return jsonify(ok=False, error="Cannot sign: the message must be a JSON object."), 400
        signed = runtime.authenticator.sign(message)
        return jsonify(ok=True, signed_json=json.dumps(signed, indent=2), key_source=runtime.authenticator.key_source)

    @app.post("/auth/mode")
    def auth_mode():
        if request.is_json:
            body = request.get_json(silent=True)
            wanted = body.get("require") if isinstance(body, dict) else None
            if not isinstance(wanted, bool):
                return jsonify(ok=False, error="'require' must be true or false."), 400
            runtime.set_require_auth(wanted)
            return jsonify(ok=True, required=runtime.require_auth)
        runtime.set_require_auth(request.form.get("require") == "1")
        flash("Authentication is now REQUIRED: unsigned messages are rejected." if runtime.require_auth
              else "Authentication is now OPTIONAL: unsigned messages skip the HMAC check (a bad tag is still rejected).", "info")
        return redirect(url_for("validate_message" if request.form.get("next") == "validate" else "dashboard"))

    @app.post("/auth/demo")
    def auth_demo():
        results = runtime.run_auth_demo()
        accepted = sum(row["decision"] == "ACCEPTED" for row in results)
        flash(f"Authentication demo complete: {accepted} accepted, {len(results) - accepted} rejected. "
              "Authentication is now REQUIRED. All messages are synthetic.", "success")
        return redirect(url_for("dashboard"))

    @app.errorhandler(413)
    def request_too_large(_error):
        flash("Request too large. Keep synthetic JSON under 64 KiB.", "danger")
        return redirect(url_for("validate_message")), 303

    return app


app = create_app()


if __name__ == "__main__":
    # Bind only to loopback. This is a local learning prototype, not a public service.
    url = "http://127.0.0.1:8765"
    if os.environ.get("SENTINEL_NO_BROWSER") != "1":
        Timer(1.0, lambda: webbrowser.open(url)).start()
    print("\nSENTINEL / local synthetic-message simulator")
    print("Open: " + url)
    print("Local only. No real satellite or command-system connection.\n")
    app.run(host="127.0.0.1", port=8765, debug=False, threaded=True)
