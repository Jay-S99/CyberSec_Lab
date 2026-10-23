import sqlite3

from flask import current_app, g, jsonify

from database import get_db
from security.responses import wants_json_response
from security.security_log import record_authorization_denied


def forbidden(_error):
    if not g.get("authorization_denial_logged"):
        g.authorization_denial_logged = True
        user = g.get("user")
        try:
            record_authorization_denied(
                get_db(),
                user["id"] if user is not None else None,
                g.get("authorization_operation", "protected_resource"),
            )
        except sqlite3.Error:
            current_app.logger.error("Authorization event could not be recorded.")
    if wants_json_response():
        return jsonify(error="forbidden", message="Access denied."), 403
    from auth.login import _render

    return _render("errors/403.html", status=403)


def init_app(app):
    app.register_error_handler(403, forbidden)
    app.register_error_handler(404, not_found)


def not_found(_error):
    if wants_json_response():
        return jsonify(error="not_found"), 404
    from auth.login import _render

    return _render("errors/404.html", status=404)
